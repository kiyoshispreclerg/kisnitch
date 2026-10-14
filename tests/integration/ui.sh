#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# End-to-end tests of kisnitch-gtk (phase 6 acceptance criteria), in a
# network namespace of their own (never the host's network), on a virtual
# X server (Xvfb):
#
#   - a daemon connects to the UI; a connection without rules is asked in
#     the pop-up; when the countdown ends the UI's default action applies
#     and becomes a rule the daemon saves (allow: curl works; deny: it
#     doesn't);
#   - a click (Alt+A, the "Allow" button, through xdotool) answers before
#     the countdown;
#   - the UI's RSS once idle.
#
# With our daemon (KISNITCHD) and, if there is one, the original Go daemon
# (OPENSNITCHD, default /usr/bin/opensnitchd; set it empty to skip): the
# interoperability matrix of docs/PORTING.md, the "our UI" column.
#
# As root this uses `unshare -nm`; otherwise `unshare -Urnm` where the
# kernel allows it. Needs Xvfb, curl, python3 and nft; xdotool for the
# click test.
#
# KISNITCHD, KISNITCH_GTK: paths of our binaries (default build/).

set -u

here=$(cd "$(dirname "$0")" && pwd)
KISNITCHD=${KISNITCHD:-$here/../../build/kisnitchd}
KISNITCH_GTK=${KISNITCH_GTK:-$here/../../build/kisnitch-gtk}
OPENSNITCHD=${OPENSNITCHD-/usr/bin/opensnitchd}

if [ -z "${KS_TEST_IN_NETNS:-}" ]; then
    for tool in Xvfb curl python3 nft unshare ip; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "SKIP (ui): $tool not found"
            exit 0
        fi
    done
    if [ ! -x "$KISNITCH_GTK" ]; then
        echo "SKIP (ui): $KISNITCH_GTK not built"
        exit 0
    fi
    if [ "$(id -u)" -eq 0 ]; then
        ns="unshare -nm"
    else
        ns="unshare -Urnm"
    fi
    if ! $ns true 2>/dev/null; then
        echo "SKIP (ui): can't create a network namespace (run as root?)"
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
xvfb_pid=
web_pid=
ui_pid=
daemon_pid=

cleanup() {
    [ -n "$daemon_pid" ] && kill -9 "$daemon_pid" 2>/dev/null
    [ -n "$ui_pid" ] && kill "$ui_pid" 2>/dev/null
    [ -n "$web_pid" ] && kill "$web_pid" 2>/dev/null
    [ -n "$xvfb_pid" ] && kill "$xvfb_pid" 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

ok() { total=$((total + 1)); echo "  ok   $1"; }
fail() {
    total=$((total + 1)); fails=$((fails + 1))
    echo "  FAIL $1"
    for f in daemon.log ui.log; do
        if [ -f "$work/$f" ]; then
            echo "  --- $f (last lines):"
            grep -v 'parsing .desktop' "$work/$f" | tail -n 12 | sed 's/^/  | /'
        fi
    done
}

# a display of our own
display=:$((90 + $$ % 9))
Xvfb "$display" -screen 0 1024x768x24 -nolisten tcp >/dev/null 2>&1 &
xvfb_pid=$!
export DISPLAY=$display
i=0
until [ -e "/tmp/.X11-unix/X${display#:}" ]; do
    i=$((i + 1)); [ $i -gt 50 ] && { echo "FAIL: Xvfb didn't start"; exit 1; }
    sleep 0.1
done

port=18080
mkdir -p "$work/www" && echo hello > "$work/www/index.html"
python3 -m http.server --bind 127.0.0.1 --directory "$work/www" $port >/dev/null 2>&1 &
web_pid=$!
fetch() {
    curl -s --max-time "${1:-3}" "http://127.0.0.1:$port/index.html" 2>/dev/null | grep -q hello
}
i=0
until fetch; do
    i=$((i + 1)); [ $i -gt 50 ] && { echo "FAIL: test server didn't start"; exit 1; }
    sleep 0.1
done

sock=$work/ui.sock

# ui_start <default_action> <default_duration> <default_timeout>
ui_start() {
    rm -rf "$work/home" && mkdir -p "$work/home/.config/opensnitch" "$work/run"
    cat > "$work/home/.config/opensnitch/settings.conf" <<EOF
[global]
default_action=$1
default_duration=$2
default_target=0
default_timeout=$3
EOF
    HOME=$work/home XDG_CONFIG_HOME=$work/home/.config XDG_RUNTIME_DIR=$work/run \
        "$KISNITCH_GTK" --socket "unix://$sock" --debug > "$work/ui.log" 2>&1 &
    ui_pid=$!
    i=0
    until [ -S "$sock" ]; do
        i=$((i + 1)); [ $i -gt 50 ] && return 1
        sleep 0.1
    done
}

ui_stop() {
    [ -n "$ui_pid" ] && kill "$ui_pid" 2>/dev/null && wait "$ui_pid" 2>/dev/null
    ui_pid=
}

# daemon_start <binary>
daemon_start() {
    rm -rf "$work/rules" && mkdir -p "$work/rules"
    cat > "$work/config.json" <<EOF
{
    "Server": {"Address": "unix://$sock", "LogFile": ""},
    "DefaultAction": "deny",
    "DefaultDuration": "once",
    "InterceptUnknown": false,
    "ProcMonitorMethod": "proc",
    "LogLevel": 0,
    "LogUTC": true,
    "LogMicro": false,
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
    # connected: the UI logs the Notifications channel
    i=0
    until grep -q 'channel started' "$work/ui.log" 2>/dev/null; do
        i=$((i + 1)); [ $i -gt 100 ] && return 1
        sleep 0.1
    done
}

daemon_stop() {
    [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null && wait "$daemon_pid" 2>/dev/null
    daemon_pid=
    nft flush ruleset 2>/dev/null
}

# rule_has <file> <text>...
rule_has() {
    f=$1; shift
    [ -f "$f" ] || return 1
    for t in "$@"; do
        tr -d ' \n' < "$f" | grep -qF "$t" || return 1
    done
}

curl_bin=$(readlink -f "$(command -v curl)")
curl_slug=$(printf '%s' "$curl_bin" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]\{1,\}/-/g; s/^-//; s/-$//')

run_daemon() { # <label> <binary>
    label=$1
    bin=$2
    echo "== $label + kisnitch-gtk"

    # 1. the countdown ends: allow
    if ! ui_start 1 8 2 || ! daemon_start "$bin"; then
        fail "$label: the daemon connects to the UI"
        daemon_stop; ui_stop; return
    fi
    ok "$label: the daemon connects to the UI"
    if fetch 15; then
        ok "$label: timeout with default allow: curl works"
    else
        fail "$label: timeout with default allow: curl works"
    fi
    f=$work/rules/allow-always-simple-$curl_slug.json
    if rule_has "$f" '"action":"allow"' '"duration":"always"' '"operand":"process.path"' \
        "\"data\":\"$curl_bin\"" '"type":"simple"'; then
        ok "$label: the answer became rule $(basename "$f")"
    else
        fail "$label: the answer became rule $(basename "$f") ($(ls "$work/rules"))"
    fi
    if fetch 3; then
        ok "$label: the rule applies without asking again"
    else
        fail "$label: the rule applies without asking again"
    fi

    # the RSS of the UI, idle, connected to a daemon
    if [ "$label" = kisnitchd ]; then
        sleep 2
        rss=$(awk '/^VmRSS/ {print $2}' "/proc/$ui_pid/status")
        echo "  info kisnitch-gtk VmRSS, idle and connected: $rss kB"
    fi
    daemon_stop; ui_stop

    # 2. the countdown ends: deny
    if ui_start 0 8 2 && daemon_start "$bin"; then
        if fetch 6; then
            fail "$label: timeout with default deny: curl fails"
        else
            ok "$label: timeout with default deny: curl fails"
        fi
        if [ -f "$work/rules/deny-always-simple-$curl_slug.json" ]; then
            ok "$label: deny rule saved"
        else
            fail "$label: deny rule saved ($(ls "$work/rules"))"
        fi
    else
        fail "$label: the daemon connects to the UI (deny)"
    fi
    daemon_stop; ui_stop

    # 3. a click on Allow before the countdown (default deny, 60 s)
    if command -v xdotool >/dev/null 2>&1; then
        if ui_start 0 0 60 && daemon_start "$bin"; then
            ( fetch 30 && touch "$work/fetched" ) &
            fetch_pid=$!
            wid=
            i=0
            while [ -z "$wid" ] && [ $i -lt 100 ]; do
                wid=$(xdotool search --onlyvisible --name '^Kisnitch v' 2>/dev/null | head -n 1)
                i=$((i + 1)); sleep 0.1
            done
            start=$(date +%s)
            if [ -n "$wid" ]; then
                xdotool windowfocus --sync "$wid" 2>/dev/null
                xdotool key --window "$wid" alt+a
            fi
            wait $fetch_pid
            took=$(( $(date +%s) - start ))
            if [ -f "$work/fetched" ] && [ $took -lt 20 ]; then
                ok "$label: Allow clicked: curl works (in ${took}s)"
            else
                fail "$label: Allow clicked: curl works (window: ${wid:-none})"
            fi
            rm -f "$work/fetched"
            if rule_has "$work/rules/allow-once-simple-$curl_slug.json" 2>/dev/null; then
                fail "$label: a rule for once is not saved"
            else
                ok "$label: a rule for once is not saved"
            fi
        else
            fail "$label: the daemon connects to the UI (click)"
        fi
        daemon_stop; ui_stop
    else
        echo "  skip click test: xdotool not found"
    fi
}

run_daemon kisnitchd "$KISNITCHD"
if [ -n "$OPENSNITCHD" ] && [ -x "$OPENSNITCHD" ]; then
    run_daemon "opensnitchd $("$OPENSNITCHD" -version 2>/dev/null | tail -n 1)" "$OPENSNITCHD"
else
    echo "  skip the original daemon: OPENSNITCHD not found"
fi

echo "ui: $((total - fails))/$total passed"
[ $fails -eq 0 ]
