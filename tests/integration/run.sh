#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# End-to-end tests of kisnitchd (phase 3 acceptance criteria), inside a
# network namespace of their own: never the host's network.
#
#   - a "deny" rule for curl makes curl fail; an "allow" rule lets it work;
#   - a connection without rules gets the DefaultAction;
#   - after the daemon is killed, nothing of ours is left in nftables (and
#     with QueueBypass the network keeps working even after a SIGKILL);
#   - after `nft flush ruleset`, the rules come back within the monitor
#     interval.
#
# As root this uses `unshare -n`; otherwise `unshare -Urn` (an unprivileged
# user namespace), where the kernel allows it. Needs curl, python3 and nft.
#
# KISNITCHD: path of the daemon (default: build/kisnitchd).

set -u

here=$(cd "$(dirname "$0")" && pwd)
KISNITCHD=${KISNITCHD:-$here/../../build/kisnitchd}

if [ -z "${KS_TEST_IN_NETNS:-}" ]; then
    for tool in curl python3 nft unshare ip; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "SKIP: $tool not found"
            exit 0
        fi
    done
    if [ "$(id -u)" -eq 0 ]; then
        ns="unshare -n"
    else
        ns="unshare -Urn"
    fi
    if ! $ns true 2>/dev/null; then
        echo "SKIP: can't create a network namespace (run as root?)"
        exit 0
    fi
    KS_TEST_IN_NETNS=1 KISNITCHD="$KISNITCHD" exec $ns sh "$0" "$@"
fi

# ---- inside the namespace ------------------------------------------------

ip link set lo up
work=$(mktemp -d)
daemon_pid=
server_pid=
fails=0
total=0

cleanup() {
    [ -n "$daemon_pid" ] && kill -9 "$daemon_pid" 2>/dev/null
    [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

ok() { total=$((total + 1)); echo "  ok   $1"; }
fail() {
    total=$((total + 1)); fails=$((fails + 1))
    echo "  FAIL $1"
    if [ -f "$work/daemon.log" ]; then
        echo "  --- daemon log (last lines):"
        tail -n 15 "$work/daemon.log" | sed 's/^/  | /'
    fi
}

curl_bin=$(readlink -f "$(command -v curl)")
port=18080
mkdir -p "$work/www" && echo hello > "$work/www/index.html"
python3 -m http.server --bind 127.0.0.1 --directory "$work/www" $port \
    >/dev/null 2>&1 &
server_pid=$!

fetch() { # succeeds if the page is fetched
    curl -s --max-time 3 "http://127.0.0.1:$port/index.html" 2>/dev/null | grep -q hello
}

# Wait for the server (before any daemon runs).
i=0
until fetch; do
    i=$((i + 1)); [ $i -gt 50 ] && { echo "FAIL: test server didn't start"; exit 1; }
    sleep 0.1
done

# config <default action> <queue bypass> <monitor interval>
write_config() {
    mkdir -p "$work/rules"
    cat > "$work/config.json" <<EOF
{
    "Server": {"Address": "unix:///tmp/kisnitch-test-none.sock", "LogFile": ""},
    "DefaultAction": "$1",
    "DefaultDuration": "once",
    "InterceptUnknown": false,
    "ProcMonitorMethod": "proc",
    "LogLevel": 0,
    "LogUTC": true,
    "LogMicro": false,
    "Firewall": "nftables",
    "FwOptions": {
        "ConfigPath": "$work/system-fw.json",
        "MonitorInterval": "$3",
        "QueueBypass": $2
    },
    "Rules": {"Path": "$work/rules", "EnableChecksums": false},
    "Internal": {"GCPercent": 100, "FlushConnsOnStart": true}
}
EOF
}

# rule <name> <action> <process path>
write_rule() {
    cat > "$work/rules/$1.json" <<EOF
{
    "created": "2026-01-01T00:00:00Z",
    "updated": "2026-01-01T00:00:00Z",
    "name": "$1",
    "description": "",
    "enabled": true,
    "precedence": false,
    "nolog": false,
    "action": "$2",
    "duration": "always",
    "operator": {
        "type": "simple",
        "operand": "process.path",
        "sensitive": false,
        "data": "$3",
        "list": []
    }
}
EOF
}

start_daemon() {
    : > "$work/daemon.log"
    "$KISNITCHD" -config-file "$work/config.json" -log-file "$work/daemon.log" \
        -debug >/dev/null 2>"$work/daemon.err" &
    daemon_pid=$!
    i=0
    until grep -q "Running on netfilter queue" "$work/daemon.log" 2>/dev/null; do
        i=$((i + 1))
        if [ $i -gt 100 ] || ! kill -0 "$daemon_pid" 2>/dev/null; then
            fail "daemon didn't start"
            return 1
        fi
        sleep 0.1
    done
}

# Stops the daemon; on SIGTERM/SIGINT it must exit cleanly (status 0,
# nothing from the sanitizers when built with them).
stop_daemon() { # stop_daemon [signal]
    sig=${1:-TERM}
    kill "-$sig" "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
    st=$?
    daemon_pid=
    if [ "$sig" != KILL ]; then
        if [ "$st" -ne 0 ] || grep -qE "Sanitizer|runtime error" "$work/daemon.err"; then
            fail "daemon exit on SIG$sig (status $st)"
            sed 's/^/  ! /' "$work/daemon.err" | head -n 30
        fi
    fi
}

ours_in_nft() { nft list ruleset 2>/dev/null | grep -q opensnitch; }

echo "kisnitchd integration tests ($KISNITCHD)"

# 1. deny / allow rules for curl ------------------------------------------
# Each rule goes against the DefaultAction, so the verdict must be the rule's.
write_config allow true 10s
rm -f "$work/rules"/*.json
write_rule 000-curl deny "$curl_bin"
start_daemon || exit 1
if fetch; then fail "deny rule: curl got through"; else ok "deny rule blocks curl"; fi
grep -q "curl.*(000-curl)" "$work/daemon.log" && ok "deny verdict found curl's process" ||
    fail "no deny verdict for curl in the log"
stop_daemon

write_config deny true 10s
rm -f "$work/rules"/*.json
write_rule 000-curl allow "$curl_bin"
start_daemon || exit 1
if fetch; then ok "allow rule lets curl through"; else fail "allow rule: curl blocked"; fi
grep -q "000-curl" "$work/daemon.log" && ok "the verdict names the rule" ||
    fail "no log line for the rule"
stop_daemon

write_config allow true 10s
write_rule 000-curl reject "$curl_bin"
start_daemon || exit 1
if fetch; then fail "reject rule: curl got through"; else ok "reject rule blocks curl"; fi
stop_daemon

# 2. no rule: DefaultAction -----------------------------------------------
rm -f "$work/rules"/*.json
write_config deny true 10s
start_daemon || exit 1
if fetch; then fail "DefaultAction deny: curl got through"; else ok "DefaultAction deny applies"; fi
stop_daemon

write_config allow true 10s
start_daemon || exit 1
if fetch; then ok "DefaultAction allow applies"; else fail "DefaultAction allow: curl blocked"; fi

# 3. cleanup on exit ------------------------------------------------------
ours_in_nft && ok "rules installed while running" || fail "no rules while running"
stop_daemon TERM
if ours_in_nft; then fail "SIGTERM: rules left behind"; else ok "SIGTERM removes our rules"; fi

start_daemon || exit 1
stop_daemon INT
if ours_in_nft; then fail "SIGINT: rules left behind"; else ok "SIGINT removes our rules"; fi

write_config deny true 10s
start_daemon || exit 1
stop_daemon KILL
ours_in_nft && ok "SIGKILL leaves the rules (as upstream)" || fail "SIGKILL: rules gone?"
if fetch; then ok "QueueBypass: network works with the daemon dead"; else
    fail "QueueBypass: network blocked with the daemon dead"; fi

write_config deny false 10s
start_daemon || exit 1
nft list ruleset | grep -q bypass && fail "QueueBypass false: bypass flag set" ||
    ok "QueueBypass false: no bypass flag"
n=$(nft list ruleset | grep -c "queue")
[ "$n" -eq 3 ] && ok "restart after SIGKILL: no duplicated rules" ||
    fail "restart after SIGKILL: $n queue rules"
stop_daemon
if ours_in_nft; then fail "cleanup: rules left behind"; else ok "cleanup after restart"; fi

# 4. external flush --------------------------------------------------------
write_config allow true 1s
start_daemon || exit 1
nft flush ruleset
i=0
until ours_in_nft; do
    i=$((i + 1))
    if [ $i -gt 40 ]; then break; fi
    sleep 0.1
done
if ours_in_nft; then ok "rules reinstalled after nft flush ruleset"; else
    fail "rules not reinstalled after flush"; fi
n=$(nft list ruleset | grep -c "queue")
[ "$n" -eq 3 ] && ok "reinstalled rules are complete" || fail "$n queue rules after reload"
stop_daemon
if ours_in_nft; then fail "cleanup after reload: rules left"; else ok "cleanup after reload"; fi

echo "tests/integration/run.sh: $((total - fails))/$total passed"
[ "$fails" -eq 0 ]
