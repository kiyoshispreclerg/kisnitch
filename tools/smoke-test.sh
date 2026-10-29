#!/bin/sh
# Checks an installed kisnitch: both versions match, every library the
# binaries need is there, the data files are in place, and the UI starts on a
# virtual X screen and stays up. Touches nothing of the user's: HOME lives in
# a temporary folder.
# Usage: tools/smoke-test.sh      (from the repository root; needs xvfb-run)
set -eu

[ -f config.mk ] || { echo "run it from the repository root" >&2; exit 2; }
version=$(sed -n 's/^VERSION *= *//p' config.mk)
upstream=$(sed -n 's/^UPSTREAM_VERSION *= *//p' config.mk)
full=$version+os$upstream

work=$(mktemp -d /tmp/ks-smoke.XXXXXX)
trap 'rm -rf "$work"' EXIT
export HOME=$work
unset XDG_DATA_HOME XDG_CONFIG_HOME XDG_RUNTIME_DIR

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

echo "== version"
got=$(kisnitchd --version 2>&1) || fail "kisnitchd --version: $got"
[ "$got" = "$full" ] || fail "kisnitchd --version: \"$got\", expected \"$full\""
got=$(kisnitch-gtk --version 2>&1) || fail "kisnitch-gtk --version: $got"
[ "$got" = "kisnitch-gtk $full" ] || fail "kisnitch-gtk --version: \"$got\", expected \"kisnitch-gtk $full\""

echo "== libraries"
for b in kisnitchd kisnitch-gtk; do
	p=$(command -v "$b") || fail "$b is not installed"
	if ldd "$p" | grep "not found"; then
		fail "$b needs libraries the package does not depend on"
	fi
done

echo "== data"
for f in /usr/share/applications/kisnitch.desktop \
	/usr/share/metainfo/io.github.kisnitch.metainfo.xml \
	/usr/share/icons/hicolor/scalable/apps/kisnitch.svg \
	/etc/opensnitchd/default-config.json /etc/opensnitchd/system-fw.json \
	/etc/init.d/kisnitch /etc/xdg/autostart/kisnitch.desktop; do
	[ -f "$f" ] || fail "$f is missing"
done

echo "== service files"
[ -x /etc/init.d/kisnitch ] && sh -n /etc/init.d/kisnitch || fail "init script"
[ -f /usr/lib/systemd/system/kisnitch.service ] || fail "systemd unit is missing"
ls /etc/opensnitchd/rules/*.json >/dev/null 2>&1 || fail "no default rules in /etc/opensnitchd/rules"

echo "== window"
# Without a daemon it just waits for one: still running after 5 s means ok.
rc=0
xvfb-run -a -s "-screen 0 1280x720x24" timeout 5 env NO_AT_BRIDGE=1 kisnitch-gtk --socket "unix://$work/ui.sock" >/dev/null 2>&1 || rc=$?
[ "$rc" = 124 ] || fail "kisnitch-gtk exited with $rc before 5 s"
echo "OK"
