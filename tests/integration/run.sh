#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# End-to-end tests of kisnitchd (phase 3, 4 and 5 acceptance criteria),
# inside a network namespace of their own: never the host's network.
#
#   - a "deny" rule for curl makes curl fail; an "allow" rule lets it work;
#   - a connection without rules gets the DefaultAction;
#   - after the daemon is killed, nothing of ours is left in nftables (and
#     with QueueBypass the network keeps working even after a SIGKILL);
#   - after `nft flush ruleset`, the rules come back within the monitor
#     interval;
#   - rules on dest.host decide `curl https://exemplo.test`, resolved through
#     the C library by a test DNS server (tests/integration/dns_server.py).
#     The namespace also gets its own mounts, so /etc/resolv.conf and
#     /etc/nsswitch.conf are replaced only inside it: plain resolv.conf
#     resolution, as on systems without systemd-resolved;
#   - with a UI (tests/integration/fake_ui.py, a grpcio server like the real
#     UI's): connections without rules are asked, the answer decides them
#     and becomes a rule, stats arrive with Ping, configuration changes from
#     the UI are applied and saved, other traffic flows while a question is
#     pending, a closed UI means DefaultAction without hanging, and the
#     daemon reconnects when the UI comes back. Skipped without python3's
#     grpcio and grpc_tools.
#
# As root this uses `unshare -nm`; otherwise `unshare -Urnm` (an
# unprivileged user namespace), where the kernel allows it; without a mount
# namespace the DNS tests are skipped. Needs curl, python3 and nft; openssl
# for HTTPS (otherwise the DNS tests use HTTP).
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
    mountns=1
    if $ns -m true 2>/dev/null; then
        ns="$ns -m"
    elif $ns true 2>/dev/null; then
        mountns=
    else
        echo "SKIP: can't create a network namespace (run as root?)"
        exit 0
    fi
    KS_TEST_IN_NETNS=1 KS_TEST_MOUNTNS=$mountns KISNITCHD="$KISNITCHD" \
        exec $ns sh "$0" "$@"
fi

# ---- inside the namespace ------------------------------------------------

ip link set lo up
work=$(mktemp -d)
daemon_pid=
server_pid=
fails=0
total=0

dns_pid=
web_pid=
ui_pid=
extra_pids=

cleanup() {
    [ -n "$daemon_pid" ] && kill -9 "$daemon_pid" 2>/dev/null
    [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
    [ -n "$dns_pid" ] && kill "$dns_pid" 2>/dev/null
    [ -n "$web_pid" ] && kill "$web_pid" 2>/dev/null
    [ -n "$ui_pid" ] && kill "$ui_pid" 2>/dev/null
    for p in $extra_pids; do kill "$p" 2>/dev/null; done
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

# config <default action> <queue bypass> <monitor interval> [UI address]
write_config() {
    mkdir -p "$work/rules"
    cat > "$work/config.json" <<EOF
{
    "Server": {"Address": "${4:-unix:///tmp/kisnitch-test-none.sock}", "LogFile": ""},
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

# rule_json <name> <action> <operator JSON>
rule_json() {
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
    "operator": $3
}
EOF
}

# host_rule <name> <action> <host>: dest.host only (DNS queries for the
# host match too: their dest.host is the name asked for).
host_rule() {
    rule_json "$1" "$2" "{\"type\": \"simple\", \"operand\": \"dest.host\",
        \"sensitive\": false, \"data\": \"$3\", \"list\": []}"
}

# host_tcp_rule <name> <action> <host>: dest.host and TCP, so only the
# connection to the resolved IP matches, not the DNS query.
host_tcp_rule() {
    rule_json "$1" "$2" "{\"type\": \"list\", \"operand\": \"list\",
        \"sensitive\": false, \"data\": \"\", \"list\": [
        {\"type\": \"simple\", \"operand\": \"dest.host\", \"sensitive\": false,
         \"data\": \"$3\", \"list\": null},
        {\"type\": \"simple\", \"operand\": \"protocol\", \"sensitive\": false,
         \"data\": \"tcp\", \"list\": null}]}"
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

# 5. DNS: rules on dest.host -----------------------------------------------
if [ -z "${KS_TEST_MOUNTNS:-}" ]; then
    echo "  skip DNS tests: no mount namespace to replace /etc/resolv.conf"
else
    # The web server's address must not be loopback: dns.Track ignores
    # answers in 127.0.0.0/8.
    ip addr add 10.99.0.1/32 dev lo
    echo "nameserver 127.0.0.1" > "$work/resolv.conf"
    printf 'hosts: files dns\n' > "$work/nsswitch.conf"
    mount --bind "$work/resolv.conf" /etc/resolv.conf &&
        mount --bind "$work/nsswitch.conf" /etc/nsswitch.conf ||
        fail "can't replace /etc/resolv.conf in the mount namespace"

    python3 "$here/dns_server.py" 127.0.0.1 53 10.99.0.1 >/dev/null 2>&1 &
    dns_pid=$!
    scheme=http
    tls=
    if command -v openssl >/dev/null 2>&1 &&
        openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=exemplo.test \
            -addext "subjectAltName=DNS:exemplo.test,DNS:alias.exemplo.test" \
            -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1; then
        scheme=https
        tls="$work/cert.pem $work/key.pem"
    else
        echo "  (openssl not available: DNS tests over HTTP)"
    fi
    # shellcheck disable=SC2086 # $tls is two words or none
    python3 "$here/web_server.py" 10.99.0.1 8443 "$work/www" $tls >/dev/null 2>&1 &
    web_pid=$!

    fetch_host() { # fetch_host <name>: succeeds if the page is fetched
        if [ "$scheme" = https ]; then
            curl -s --max-time 5 --cacert "$work/cert.pem" \
                "https://$1:8443/index.html" 2>/dev/null | grep -q hello
        else
            curl -s --max-time 5 "http://$1:8443/index.html" 2>/dev/null | grep -q hello
        fi
    }
    i=0
    until fetch_host exemplo.test; do
        i=$((i + 1)); [ $i -gt 50 ] && { fail "DNS test servers didn't start"; break; }
        sleep 0.1
    done

    # Deny the host: the query and the connection both match.
    rm -f "$work/rules"/*.json
    write_config allow true 10s
    host_rule 000-host deny exemplo.test
    start_daemon || exit 1
    if fetch_host exemplo.test; then fail "dest.host deny: curl $scheme got through"; else
        ok "dest.host deny blocks curl $scheme://exemplo.test"; fi
    stop_daemon

    # Deny only TCP to the host: the query goes out, its answer is tracked
    # from the queue and the connection to 10.99.0.1 is denied by name.
    rm -f "$work/rules"/*.json
    host_tcp_rule 000-host-tcp deny exemplo.test
    start_daemon || exit 1
    if fetch_host exemplo.test; then fail "dest.host+tcp deny: curl got through"; else
        ok "dest.host deny applies to the resolved IP"; fi
    grep -q "New DNS record: 10.99.0.1 -> exemplo.test" "$work/daemon.log" &&
        ok "the DNS answer was tracked from the queue" || fail "DNS answer not tracked"
    grep -q "exemplo.test (10.99.0.1):8443.*(000-host-tcp)" "$work/daemon.log" &&
        ok "the connection was denied by host name" || fail "no deny verdict by host name"
    stop_daemon

    # CNAMEs: dest.host is the name asked for, not the canonical one.
    rm -f "$work/rules"/*.json
    host_tcp_rule 000-alias deny alias.exemplo.test
    start_daemon || exit 1
    if fetch_host exemplo.test; then ok "the canonical name isn't affected"; else
        fail "CNAME rule blocked the canonical name"; fi
    if fetch_host alias.exemplo.test; then fail "CNAME: curl got through"; else
        ok "dest.host follows CNAMEs back to the name asked for"; fi
    # As upstream: the cache now maps exemplo.test back to the alias, so
    # the canonical name is denied too (docs/UPSTREAM.md, upstream bugs).
    if fetch_host exemplo.test; then fail "canonical name after the alias: allowed"; else
        ok "after the alias, the canonical name maps to it (as upstream)"; fi
    stop_daemon

    # Allow the host against DefaultAction deny.
    rm -f "$work/rules"/*.json
    write_config deny true 10s
    host_rule 000-host allow exemplo.test
    start_daemon || exit 1
    if fetch_host exemplo.test; then ok "dest.host allow lets curl $scheme through"; else
        fail "dest.host allow: curl blocked"; fi
    if fetch; then fail "DefaultAction deny: other hosts got through"; else
        ok "other destinations still get the DefaultAction"; fi
    stop_daemon
fi


# 6. UI protocol -----------------------------------------------------------
if ! python3 -W ignore -c "import grpc, grpc_tools" 2>/dev/null; then
    echo "  skip UI tests: python3 grpcio and grpc_tools not installed"
else
    mkdir -p "$work/pb" "$work/ctl"
    python3 -W ignore -m grpc_tools.protoc -I"$here/../../proto" \
        --python_out="$work/pb" --grpc_python_out="$work/pb" \
        "$here/../../proto/ui.proto" 2>/dev/null
    ui_sock="$work/ui.sock"
    : > "$work/ui.log"

    # More web servers: one port per question.
    for p in 18081 18082 18083; do
        python3 -m http.server --bind 127.0.0.1 --directory "$work/www" $p \
            >/dev/null 2>&1 &
        extra_pids="$extra_pids $!"
    done
    fetch_port() { # fetch_port <port> [max time]
        curl -s --max-time "${2:-3}" "http://127.0.0.1:$1/index.html" 2>/dev/null |
            grep -q hello
    }
    wait_for() { # wait_for <seconds> <command...>
        n=$(($1 * 10)); shift
        while ! "$@"; do
            n=$((n - 1)); [ $n -le 0 ] && return 1
            sleep 0.1
        done
    }
    ui_count() { grep -c "$1" "$work/ui.log" 2>/dev/null; }
    ui_saw() { grep -q "$1" "$work/ui.log" 2>/dev/null; }
    log_has() { grep -q "$1" "$work/daemon.log" 2>/dev/null; }
    start_ui() {
        rm -f "$ui_sock"
        python3 "$here/fake_ui.py" "$work/pb" "$ui_sock" "$work/ui.log" "$work/ctl" \
            >"$work/ui.err" 2>&1 &
        ui_pid=$!
        wait_for 10 test -S "$ui_sock" || fail "fake UI didn't start"
    }
    stop_ui() { kill "$ui_pid" 2>/dev/null; wait "$ui_pid" 2>/dev/null; ui_pid=; }
    for p in 18081 18082 18083; do
        wait_for 5 fetch_port $p 1 || fail "web server $p didn't start"
    done

    rm -f "$work/rules"/*.json
    write_config deny true 10s "unix://$ui_sock"
    echo '{"DefaultAction": "deny"}' > "$work/ctl/ui_config"
    echo allow > "$work/ctl/ask"
    echo always > "$work/ctl/duration"
    start_ui
    start_daemon || exit 1

    wait_for 10 ui_saw '"rpc": "Subscribe"' && ok "the daemon subscribes to the UI" ||
        fail "no Subscribe"
    wait_for 5 ui_saw '"rpc": "NotificationReply", "id": 0' &&
        ok "the notifications channel opens (hello reply)" || fail "no notifications channel"

    # A connection without rules is asked; "allow, always" lets it through
    # and is saved.
    if fetch_port 18080 5; then ok "UI answers allow: curl gets through"; else
        fail "UI answered allow, but curl was blocked"; fi
    ui_saw "\"rpc\": \"AskRule\", \"path\": \"$curl_bin\"" &&
        ok "the question carries curl's path" || fail "AskRule without curl's path"
    [ -f "$work/rules/allow-18080.json" ] && ok "the answer is saved as a rule" ||
        fail "the 'always' answer wasn't saved"
    log_has "Saved new rule: allow if" && ok "the daemon logs the new rule" ||
        fail "no 'Saved new rule' log"
    asks=$(ui_count '"rpc": "AskRule"')
    fetch_port 18080 3 && [ "$(ui_count '"rpc": "AskRule"')" -eq "$asks" ] &&
        ok "the rule answers next time, without asking" || fail "asked again"

    # deny, once: blocked and not saved
    echo deny > "$work/ctl/ask"
    echo once > "$work/ctl/duration"
    if fetch_port 18081 3; then fail "UI answered deny, curl got through"; else
        ok "UI answers deny: curl is blocked"; fi
    [ -f "$work/rules/deny-18081.json" ] && fail "a 'once' answer was saved" ||
        ok "a 'once' answer isn't saved"

    # Stats arrive with Ping
    wait_for 5 ui_saw '"rpc": "Ping".*"version": "1.8.0".*"connections": [1-9]' &&
        ok "stats arrive with Ping" || fail "no Ping with stats"

    # While the UI thinks, other traffic flows; unknown connections get the
    # UI's DefaultAction meanwhile.
    echo "hang:3" > "$work/ctl/ask"
    echo always > "$work/ctl/duration"
    (fetch_port 18082 10 && echo ok > "$work/slow.ok") &
    slow=$!
    wait_for 5 ui_saw '"dst_port": 18082' || fail "the slow question didn't arrive"
    t0=$(date +%s)
    if fetch_port 18080 2; then ok "traffic with rules flows while a question is pending"; else
        fail "traffic blocked while asking"; fi
    if fetch_port 18081 1; then fail "busy UI: unknown connection allowed"; else
        ok "busy UI: unknown connections get the UI's DefaultAction (deny)"; fi
    log_has "UI is not running or busy, connected: true, running: true" &&
        ok "the daemon didn't queue a second question" || fail "no 'busy' log"
    wait "$slow"
    [ -f "$work/slow.ok" ] && ok "a slow answer is still applied" ||
        fail "the slow answer didn't let curl through"
    t1=$(date +%s)
    [ $((t1 - t0)) -le 5 ] || fail "the pending question took too long"

    # Preferences from the UI: CHANGE_CONFIG (here DefaultAction -> allow)
    python3 - "$work/config.json" "$work/ctl/notify.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["DefaultAction"] = "allow"
json.dump({"type": 6, "data": json.dumps(cfg, indent=2)}, open(sys.argv[2], "w"))
PY
    wait_for 5 ui_saw '"rpc": "NotificationReply", "id": 101, "code": 0' &&
        ok "CHANGE_CONFIG is acknowledged" || fail "no reply to CHANGE_CONFIG"
    grep -q '"DefaultAction": "allow"' "$work/config.json" &&
        ok "the new configuration is saved" || fail "configuration not saved"

    # The UI goes away: no hang, the (new) DefaultAction applies.
    stop_ui
    wait_for 5 log_has "Connection to the UI service lost" &&
        ok "the daemon notices the UI is gone" || fail "UI loss not noticed"
    t0=$(date +%s)
    if fetch_port 18083 3; then ok "UI closed: DefaultAction (allow) applies"; else
        fail "UI closed: connection blocked"; fi
    t1=$(date +%s)
    [ $((t1 - t0)) -le 2 ] && ok "UI closed: no waiting" || fail "UI closed: curl waited"

    # The UI comes back: reconnection and a new subscription.
    start_ui
    wait_for 10 sh -c "[ \$(grep -c '\"rpc\": \"Subscribe\"' '$work/ui.log') -ge 2 ]" &&
        ok "the daemon reconnects when the UI comes back" || fail "no reconnection"
    stop_daemon
    stop_ui
fi

echo "tests/integration/run.sh: $((total - fails))/$total passed"
[ "$fails" -eq 0 ]
