#!/bin/sh
# Installs the original OpenSnitch from the distribution, gives it a user's
# state (an edited config, a rule of their own, GUI settings), then installs
# the kisnitch .deb over it and checks that nothing was migrated or lost:
# the old packages are replaced, every file the user had is byte for byte the
# same, and the new daemon starts and stops through the init script.
# Usage: tools/replace-test.sh PACKAGE.deb      (as root, in a throwaway
# system; the container needs NET_ADMIN to start the daemon)
# Exit 77: the distribution has no `opensnitch` package (nothing to test).
set -eu

deb=${1:?usage: $0 PACKAGE.deb}
deb=$(readlink -f "$deb")
export DEBIAN_FRONTEND=noninteractive
export HOME=/root

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

echo "== the original OpenSnitch"
apt-get update -qq
apt-get install -y --no-install-recommends procps >/dev/null
cand=$(apt-cache policy opensnitch | sed -n 's/^ *Candidate: //p')
if [ -z "$cand" ] || [ "$cand" = "(none)" ]; then
	echo "no opensnitch package in this distribution"
	exit 77
fi
apt-get install -y --no-install-recommends opensnitch >/dev/null
echo "opensnitch $cand"
ui=
cand=$(apt-cache policy python3-opensnitch-ui | sed -n 's/^ *Candidate: //p')
if [ -n "$cand" ] && [ "$cand" != "(none)" ]; then
	apt-get install -y --no-install-recommends python3-opensnitch-ui >/dev/null
	ui=python3-opensnitch-ui
	echo "python3-opensnitch-ui $cand"
fi
[ -x /usr/bin/opensnitchd ] || fail "opensnitchd was not installed"

echo "== a user's state"
cd /etc/opensnitchd
[ -f default-config.json ] || fail "the original package has no default-config.json"
sed 's/"LogLevel": *[0-9]*/"LogLevel": 1/' default-config.json > default-config.json.new
mv default-config.json.new default-config.json
mkdir -p rules
first=$(ls rules/*.json | head -1)
sed 's/"name": *"[^"]*"/"name": "user-rule"/' "$first" > rules/zz-user-rule.json
mkdir -p /root/.config/opensnitch
printf '[global]\ndefault_timeout=17\n' > /root/.config/opensnitch/settings.conf
snap() {
	{
		find /etc/opensnitchd -type f
		find /root/.config/opensnitch -type f
	} | sort | xargs sha256sum
}
snap > /tmp/before.sums
wc -l < /tmp/before.sums | sed 's/$/ files recorded/'

echo "== installing kisnitch over it"
cd /
apt-get install -y "$deb" >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "apt could not install the package"; }
for p in opensnitch $ui; do
	st=$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null || true)
	case "$st" in
	*"not-installed"* | "") ;;
	*"config-files"*) ;;
	*) fail "$p is still installed ($st)" ;;
	esac
done
[ ! -e /usr/bin/opensnitchd ] || fail "/usr/bin/opensnitchd is still there"
dpkg -s kisnitch >/dev/null || fail "kisnitch is not installed"

echo "== the user's files"
snap > /tmp/after.sums
# everything the user had stays identical; the package may add what was missing
lost=$(comm -23 /tmp/before.sums /tmp/after.sums)
[ -z "$lost" ] || fail "files of the user were changed or removed: $lost"
for f in default-config.json system-fw.json network_aliases.json; do
	[ -f /etc/opensnitchd/$f ] || fail "/etc/opensnitchd/$f is missing"
done

echo "== programs"
kisnitchd --version
kisnitch-gtk --version
ldd /usr/sbin/kisnitchd /usr/bin/kisnitch-gtk | grep "not found" && fail "missing libraries"
[ -f /etc/init.d/kisnitch ] || fail "no init script"
[ -f /usr/lib/systemd/system/kisnitch.service ] || fail "no systemd unit"

echo "== service (init script)"
ls /etc/rc2.d/S??kisnitch >/dev/null 2>&1 || fail "not enabled for runlevel 2 (update-rc.d)"
# the postinst may have started it already; start from a known state
/etc/init.d/kisnitch stop >/dev/null 2>&1 || true
/etc/init.d/kisnitch start
sleep 3
/etc/init.d/kisnitch status || fail "the daemon is not running after start"
pgrep -x kisnitchd >/dev/null || fail "no kisnitchd process"
! pgrep -x opensnitchd >/dev/null || fail "opensnitchd is running"
/etc/init.d/kisnitch restart
sleep 2
/etc/init.d/kisnitch status || fail "the daemon is not running after restart"
/etc/init.d/kisnitch stop
sleep 1
! pgrep -x kisnitchd >/dev/null || fail "kisnitchd is still running after stop"

echo "== purge"
apt-get purge -y kisnitch >/dev/null 2>&1 || fail "purge failed"
[ ! -e /etc/init.d/kisnitch ] || fail "the init script survived the purge"
snap > /tmp/purged.sums
lost=$(comm -23 /tmp/before.sums /tmp/purged.sums)
[ -z "$lost" ] || fail "the purge touched the user's files: $lost"
echo "OK"
