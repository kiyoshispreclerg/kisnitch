#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# TLS between daemon and UI (TLS=1 builds), in a network namespace of its
# own, over TCP on 127.0.0.1 with the certificates of tests/fixtures/tls/:
#
#   - our daemon with a gRPC server in Python with TLS (grpc core, as the
#     real UI: tests/integration/fake_ui.py, FAKE_UI_TLS): mutual TLS, TLS
#     without a client certificate, an untrusted server;
#   - our UI (on Xvfb) with our daemon, and with the original Go daemon
#     (OPENSNITCHD, default /usr/bin/opensnitchd, if it exists): mutual TLS
#     works, a daemon without a client certificate is refused.
#
# KISNITCHD, KISNITCH_GTK: TLS=1 binaries (make TLS=1 BUILD=build/tls).
# As root this uses `unshare -nm`; otherwise `unshare -Urnm` where the
# kernel allows it. Needs python3 with grpcio and grpc_tools, nft, Xvfb.

set -u

here=$(cd "$(dirname "$0")" && pwd)
KISNITCHD=${KISNITCHD:-$here/../../build/tls/kisnitchd}
KISNITCH_GTK=${KISNITCH_GTK:-$here/../../build/tls/kisnitch-gtk}
OPENSNITCHD=${OPENSNITCHD-/usr/bin/opensnitchd}
certs=$here/../fixtures/tls

if [ -z "${KS_TEST_IN_NETNS:-}" ]; then
    for tool in python3 nft unshare ip; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "SKIP (tls): $tool not found"
            exit 0
        fi
    done
    if ! python3 -W ignore -c "import grpc, grpc_tools" 2>/dev/null; then
        echo "SKIP (tls): python3 grpcio and grpc_tools not installed"
        exit 0
    fi
    if [ ! -x "$KISNITCHD" ]; then
        echo "SKIP (tls): $KISNITCHD not built (make TLS=1 BUILD=build/tls)"
        exit 0
    fi
    if [ "$(id -u)" -eq 0 ]; then ns="unshare -nm"; else ns="unshare -Urnm"; fi
    if ! $ns true 2>/dev/null; then
        echo "SKIP (tls): can't create a network namespace (run as root?)"
        exit 0
    fi
    KS_TEST_IN_NETNS=1 KISNITCHD="$KISNITCHD" KISNITCH_GTK="$KISNITCH_GTK" \
        OPENSNITCHD="$OPENSNITCHD" exec $ns sh "$0" "$@"
fi

# ---- inside the namespace ------------------------------------------------

ip link set lo up
work=$(mktemp -d)
chmod 755 "$work"
fails=0
total=0
ui_pid=
daemon_pid=
xvfb_pid=

cleanup() {
    [ -n "$daemon_pid" ] && kill -9 "$daemon_pid" 2>/dev/null
    [ -n "$ui_pid" ] && kill "$ui_pid" 2>/dev/null
    [ -n "$xvfb_pid" ] && kill "$xvfb_pid" 2>/dev/null
    nft flush ruleset 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

ok() { total=$((total + 1)); echo "  ok   $1"; }
fail() {
    total=$((total + 1)); fails=$((fails + 1))
    echo "  FAIL $1"
    for f in daemon.log ui.log ui.err; do
        if [ -s "$work/$f" ]; then
            echo "  --- $f (last lines):"
            grep -v 'parsing .desktop' "$work/$f" | tail -n 8 | sed 's/^/  | /'
        fi
    done
}
wait_for() { # wait_for <seconds> <command...>
    n=$(($1 * 10)); shift
    while ! "$@"; do
        n=$((n - 1)); [ $n -le 0 ] && return 1
        sleep 0.1
    done
}
saw() { grep -q "$2" "$work/$1" 2>/dev/null; }

mkdir -p "$work/pb" "$work/ctl"
python3 -W ignore -m grpc_tools.protoc -I"$here/../../proto" \
    --python_out="$work/pb" --grpc_python_out="$work/pb" "$here/../../proto/ui.proto" 2>/dev/null
echo '{"DefaultAction": "allow"}' > "$work/ctl/ui_config"

# daemon_start <binary> <address> <auth type> <CA cert> [client cert, key]
daemon_start() {
    rm -rf "$work/rules" && mkdir -p "$work/rules"
    : > "$work/daemon.log"
    cat > "$work/config.json" <<EOF
{
    "Server": {"Address": "$2", "LogFile": "",
               "Authentication": {"Type": "$3", "TLSOptions": {
                   "CACert": "$4", "ClientCert": "${5:-}", "ClientKey": "${6:-}",
                   "SkipVerify": false, "ClientAuthType": "req-and-verify-cert"}}},
    "DefaultAction": "allow",
    "DefaultDuration": "once",
    "InterceptUnknown": false,
    "ProcMonitorMethod": "proc",
    "LogLevel": 0,
    "Firewall": "nftables",
    "FwOptions": {"ConfigPath": "$work/system-fw.json", "MonitorInterval": "15s",
                  "QueueBypass": true},
    "Rules": {"Path": "$work/rules", "EnableChecksums": false},
    "Stats": {"MaxEvents": 150, "MaxStats": 25, "Workers": 6},
    "Internal": {"GCPercent": 100, "FlushConnsOnStart": false}
}
EOF
    "$1" -config-file "$work/config.json" -rules-path "$work/rules" -debug \
        -log-file "$work/daemon.log" >/dev/null 2>&1 &
    daemon_pid=$!
}

daemon_stop() {
    [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null && wait "$daemon_pid" 2>/dev/null
    daemon_pid=
    nft flush ruleset 2>/dev/null
}

# fake_start <port> <server cert> <key> <CA or "">
fake_start() {
    : > "$work/ui.log"
    FAKE_UI_TLS="$2:$3:$4" python3 "$here/fake_ui.py" "$work/pb" "127.0.0.1:$1" \
        "$work/ui.log" "$work/ctl" > "$work/ui.err" 2>&1 &
    ui_pid=$!
    wait_for 10 saw ui.log '"rpc": "started"'
}

ui_stop() {
    [ -n "$ui_pid" ] && kill "$ui_pid" 2>/dev/null && wait "$ui_pid" 2>/dev/null
    ui_pid=
}

echo "== kisnitchd + gRPC server in Python (grpc core) with TLS"
c=$certs
fake_start 50051 "$c/server.pem" "$c/server.key" "$c/ca.pem" || fail "the Python server didn't start"
daemon_start "$KISNITCHD" 127.0.0.1:50051 tls-mutual "$c/ca.pem" "$c/client.pem" "$c/client.key"
wait_for 15 saw ui.log '"rpc": "Subscribe"' && ok "mutual TLS: the daemon subscribes" ||
    fail "mutual TLS: no Subscribe"
daemon_stop
: > "$work/ui.log"
daemon_start "$KISNITCHD" 127.0.0.1:50051 tls-simple "$c/ca.pem"
sleep 4
saw ui.log '"rpc": "Subscribe"' && fail "without a client certificate it connected" ||
    ok "without a client certificate the server refuses it"
daemon_stop
ui_stop
fake_start 50052 "$c/server.pem" "$c/server.key" "" || fail "the Python server didn't start"
daemon_start "$KISNITCHD" 127.0.0.1:50052 tls-simple "$c/other-ca.pem"
sleep 4
saw ui.log '"rpc": "Subscribe"' && fail "it trusted a server of another CA" ||
    ok "a server of another CA isn't trusted"
daemon_stop
daemon_start "$KISNITCHD" 127.0.0.1:50052 tls-simple "$c/ca.pem"
wait_for 15 saw ui.log '"rpc": "Subscribe"' && ok "tls-simple: the daemon subscribes" ||
    fail "tls-simple: no Subscribe"
daemon_stop
ui_stop

# ---- our UI ---------------------------------------------------------------
if ! command -v Xvfb >/dev/null 2>&1 || [ ! -x "$KISNITCH_GTK" ]; then
    echo "  skip our UI: Xvfb or $KISNITCH_GTK missing"
else
    display=:$((80 + $$ % 9))
    Xvfb "$display" -screen 0 1024x768x24 -nolisten tcp >/dev/null 2>&1 &
    xvfb_pid=$!
    export DISPLAY=$display
    wait_for 5 test -e "/tmp/.X11-unix/X${display#:}" || echo "FAIL: Xvfb didn't start"

    ui_start() { # ui_start <port>
        rm -rf "$work/home" && mkdir -p "$work/home/.config/opensnitch" "$work/run"
        printf '[global]\ndefault_action=allow\n' > "$work/home/.config/opensnitch/settings.conf"
        : > "$work/ui.log"
        HOME=$work/home XDG_CONFIG_HOME=$work/home/.config XDG_RUNTIME_DIR=$work/run \
            "$KISNITCH_GTK" --socket "127.0.0.1:$1" --socket-auth tls-mutual \
            --tls-cert "$c/server.pem" --tls-key "$c/server.key" --tls-ca-cert "$c/ca.pem" \
            --debug > "$work/ui.log" 2>&1 &
        ui_pid=$!
        wait_for 10 saw ui.log 'addr: '
        sleep 0.5
    }

    for d in kisnitchd opensnitchd; do
        bin=$KISNITCHD
        if [ $d = opensnitchd ]; then
            bin=$OPENSNITCHD
            if [ -z "$bin" ] || [ ! -x "$bin" ]; then
                echo "  skip the original daemon: OPENSNITCHD not found"
                continue
            fi
        fi
        echo "== $d + kisnitch-gtk with TLS"
        ui_start 50053
        daemon_start "$bin" 127.0.0.1:50053 tls-mutual "$c/ca.pem" "$c/client.pem" "$c/client.key"
        wait_for 20 saw ui.log 'channel started' && ok "$d: mutual TLS connects" ||
            fail "$d: mutual TLS didn't connect"
        daemon_stop
        : > "$work/ui.log"
        daemon_start "$bin" 127.0.0.1:50053 tls-simple "$c/ca.pem"
        sleep 5
        saw ui.log 'channel started' && fail "$d: connected without a client certificate" ||
            ok "$d: without a client certificate it's refused"
        daemon_stop
        ui_stop
    done
fi

echo "tls: $((total - fails))/$total ok"
[ $fails -eq 0 ]
