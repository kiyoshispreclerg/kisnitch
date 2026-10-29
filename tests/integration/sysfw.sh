#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The system firewall (phase 8 acceptance criteria), in a network namespace
# of their own (never the host's network):
#
#   - each system-fw.json of tests/fixtures/sysfw/ and upstream's examples
#     (daemon/data/system-fw.json, firewall/nftables/testdata/) is applied
#     by the daemon; `nft list ruleset`, normalized, must be the expected
#     one (tests/fixtures/sysfw/<name>.nft) and, if there is an upstream
#     daemon (OPENSNITCHD, default /usr/bin/opensnitchd; empty to skip),
#     the one upstream's daemon produces from the same file;
#   - nothing of ours is left once the daemon stops;
#   - a change to system-fw.json is applied while running;
#   - switching the firewall (iptables <-> nftables) in default-config.json
#     while running leaves nothing of the previous one;
#   - with a UI (tests/integration/fake_ui.py, needs python3 grpcio and
#     grpc_tools): Subscribe carries the configuration, and RELOAD_FW_RULES
#     saves the same file upstream's daemon saves, applies it, and replies
#     with the errors of the rules that couldn't be added.
#
# The normalization drops the interception rules (tested in phase 3) and
# zeroes counters. Upstream 1.6 kept the interception in tables of its own
# ("inet mangle", "inet filter"), didn't create named counters (fixed in
# 1.7) and didn't reload the firewall when default-config.json changes; to
# compare with a 1.6 daemon, those tables, the empty interception chains and
# counters are left out, and the switch test is skipped for it.
#
# UPDATE=1 rewrites the expected rulesets from our daemon.
# KISNITCHD: our daemon (default build/kisnitchd).

set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
KISNITCHD=${KISNITCHD:-$root/build/kisnitchd}
OPENSNITCHD=${OPENSNITCHD-/usr/bin/opensnitchd}
UPDATE=${UPDATE:-}

if [ -z "${KS_TEST_IN_NETNS:-}" ]; then
    for tool in nft unshare; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "SKIP (sysfw): $tool not found"
            exit 0
        fi
    done
    if [ "$(id -u)" -eq 0 ]; then
        ns="unshare -nm"
    else
        ns="unshare -Urnm"
    fi
    if ! $ns true 2>/dev/null; then
        echo "SKIP (sysfw): can't create a network namespace (run as root?)"
        exit 0
    fi
    KS_TEST_IN_NETNS=1 KISNITCHD="$KISNITCHD" OPENSNITCHD="$OPENSNITCHD" UPDATE="$UPDATE" \
        exec $ns sh "$0" "$@"
fi

# ---- inside the namespace ------------------------------------------------

work=$(mktemp -d)
pass=0
failed=0
daemon_pid=
trap 'daemon_stop; rm -rf "$work"' EXIT

ok() { pass=$((pass + 1)); echo "  ok   $1"; }
fail() { failed=$((failed + 1)); echo "  FAIL $1"; }

fixtures=$root/tests/fixtures/sysfw
upstream_daemon=$root/upstream/daemon

# A 1.6 daemon reads /etc/opensnitchd/system-fw.json whatever the config
# says: point it at ours (only inside this mount namespace).
etc_fw=/etc/opensnitchd/system-fw.json
if [ -f "$etc_fw" ]; then
    : > "$work/etc-fw.json"
    mount --bind "$work/etc-fw.json" "$etc_fw" 2>/dev/null || etc_fw=
else
    etc_fw=
fi

write_config() { # <firewall>
    cat > "$work/config.json" <<EOF
{
    "Server": {"Address": "unix://$work/ui.sock", "LogFile": ""},
    "DefaultAction": "allow",
    "DefaultDuration": "once",
    "InterceptUnknown": false,
    "ProcMonitorMethod": "proc",
    "LogLevel": 0,
    "LogUTC": true,
    "LogMicro": false,
    "Firewall": "$1",
    "FwOptions": {"ConfigPath": "$work/system-fw.json", "MonitorInterval": "0s",
                  "QueueBypass": true},
    "Rules": {"Path": "$work/rules", "EnableChecksums": false},
    "Stats": {"MaxEvents": 150, "MaxStats": 25, "Workers": 6},
    "Internal": {"GCPercent": 100, "FlushConnsOnStart": false}
}
EOF
}

set_sysfw() { # <file>
    cp "$1" "$work/system-fw.json"
    [ -n "$etc_fw" ] && cat "$1" > "$work/etc-fw.json"
    return 0
}

ruleset() {
    nft list ruleset 2>/dev/null | awk '
        /^table inet (mangle|filter) \{/ { skip = 1 }
        skip { if ($0 ~ /^\}/) skip = 0; next }
        /queue flags bypass to [0-9]+$/ && /udp sport 53 |meta l4proto != tcp ct state related,new |tcp flags / { next }
        { gsub(/packets [0-9]+ bytes [0-9]+/, "packets 0 bytes 0"); print }'
}

# Waits until the ruleset stops changing (and isn't empty if `nonempty`).
settle() { # [nonempty]
    prev=x
    i=0
    while [ $i -lt 40 ]; do
        cur=$(nft list ruleset 2>/dev/null)
        if [ "$cur" = "$prev" ] && { [ -z "${1:-}" ] || [ -n "$cur" ]; }; then
            return 0
        fi
        prev=$cur
        i=$((i + 1))
        sleep 0.25
    done
    return 1
}

daemon_start() { # <binary>
    rm -rf "$work/rules" && mkdir -p "$work/rules"
    "$1" -config-file "$work/config.json" -rules-path "$work/rules" -debug \
        -log-file "$work/daemon.log" >/dev/null 2>&1 &
    daemon_pid=$!
    sleep 0.5
    settle nonempty && return 0
    # show why in the CI log
    echo "    --- $1 log ($(kill -0 "$daemon_pid" 2>/dev/null && echo running || echo exited)):"
    tail -n 30 "$work/daemon.log" 2>&1 | sed 's/^/    | /'
    return 1
}

daemon_stop() {
    [ -n "$daemon_pid" ] || return 0
    kill -TERM "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
    daemon_pid=
}

residue() {
    nft list ruleset 2>/dev/null | grep -v '^\s*$' | grep -v -E \
        '^table (ip|ip6) (filter|mangle|nat|raw|security) \{|^\s*chain [A-Z]+ \{|type .* hook .* policy accept;|^\s*\}$'
}

# ---- 1. the expected rulesets ---------------------------------------------

cases="$fixtures/exprs.json $fixtures/drop-input.json $fixtures/disabled.json
       $upstream_daemon/data/system-fw.json
       $upstream_daemon/firewall/nftables/testdata/test-sysfw-conf.json"

apply_case() { # <label> <binary> <system-fw.json> <out>
    nft flush ruleset
    write_config nftables
    set_sysfw "$3"
    if ! daemon_start "$2"; then
        fail "$1: the ruleset settles"
    fi
    ruleset > "$4"
    daemon_stop
    left=$(residue)
    if [ -z "$left" ]; then
        ok "$1: nothing left after stop"
    else
        fail "$1: nothing left after stop:"
        echo "$left" | sed 's/^/       /'
    fi
}

upstream_ok=
upstream_16=
if [ -n "$OPENSNITCHD" ] && [ -x "$OPENSNITCHD" ]; then
    upstream_ok=1
    upstream_version=$("$OPENSNITCHD" -version 2>/dev/null | tail -n 1)
    case "$upstream_version" in 1.6.*) upstream_16=1 ;; esac
fi

# What a 1.6 daemon can be compared on (see the top of the file).
as_16() {
    awk '
        function flush() { if (n > 0 && !(empty && name ~ /^(filter_input|mangle_output)$/)) for (i = 1; i <= n; i++) print buf[i]; n = 0 }
        /^\tcounter / { skipc = 1 }
        skipc { if ($0 ~ /^\t\}/) { skipc = 2 }; if (skipc == 2) { skipc = 0; getline; if ($0 != "") print } ; next }
        /counter name / { next }
        /^\tchain / { flush(); name = $2; empty = 1; buf[++n] = $0; inchain = 1; next }
        inchain { buf[++n] = $0; if ($0 !~ /^\t\t(type |$)/ && $0 !~ /^\t\}/ && $0 != "") empty = 0;
                  if ($0 ~ /^\t\}/) { inchain = 0 }; next }
        { flush(); print }
        END { flush() }' "$1" | awk '
        /^table / { hdr = $0; nonblank = 0; body = ""; intab = 1; next }
        intab && /^\}/ { if (nonblank) { print hdr; printf "%s", body; print } ; intab = 0; next }
        intab { body = body $0 "\n"; if ($0 !~ /^[[:space:]]*$/) nonblank = 1; next }
        { print }' | awk '!NF { blank++; next } { if (!($0 ~ /^\}/)) while (blank-- > 0) print ""; blank = 0; print }'
}

nft_version=$(nft --version)
echo "== system-fw.json -> nft list ruleset ($nft_version)"
for f in $cases; do
    name=$(basename "$f" .json)
    expected=$fixtures/$name.nft
    apply_case "kisnitchd $name" "$KISNITCHD" "$f" "$work/ours.nft"
    # the expected files start with the nft version that printed them:
    # other versions print some expressions differently
    if [ -n "$UPDATE" ]; then
        { echo "# $nft_version"; cat "$work/ours.nft"; } > "$expected"
        echo "  updated $expected"
    elif [ "$(head -n 1 "$expected")" != "# $nft_version" ]; then
        echo "  skip kisnitchd $name: the expected ruleset is from $(head -n 1 "$expected" | cut -c3-)"
    elif tail -n +2 "$expected" | diff -u - "$work/ours.nft" > "$work/diff"; then
        ok "kisnitchd $name: the expected ruleset"
    else
        fail "kisnitchd $name: the expected ruleset"
        sed 's/^/       /' "$work/diff"
    fi
    if [ -n "$upstream_ok" ]; then
        apply_case "opensnitchd $upstream_version $name" "$OPENSNITCHD" "$f" "$work/theirs.nft"
        if [ -n "$upstream_16" ]; then
            as_16 "$work/theirs.nft" > "$work/theirs16.nft" && mv "$work/theirs16.nft" "$work/theirs.nft"
            as_16 "$work/ours.nft" > "$work/ours16.nft" && mv "$work/ours16.nft" "$work/ours.nft"
        fi
        if diff -u "$work/theirs.nft" "$work/ours.nft" > "$work/diff"; then
            ok "$name: same ruleset as opensnitchd $upstream_version"
        else
            fail "$name: same ruleset as opensnitchd $upstream_version"
            sed 's/^/       /' "$work/diff"
        fi
    fi
done

# ---- 2. changes while running ---------------------------------------------

echo "== system-fw.json changed while running"
nft flush ruleset
write_config nftables
set_sysfw "$upstream_daemon/data/system-fw.json"
daemon_start "$KISNITCHD"
set_sysfw "$fixtures/drop-input.json"
sleep 0.5
settle
if ruleset | grep -q 'type filter hook input priority filter; policy drop;' &&
    ruleset | grep -q 'iifname "lo" accept'; then
    ok "the new rules and policy are applied"
else
    fail "the new rules and policy are applied"
    ruleset | sed 's/^/       /'
fi
if ruleset | grep -q 'chain nat_prerouting'; then
    fail "the chains of the old configuration are gone"
else
    ok "the chains of the old configuration are gone"
fi
daemon_stop

# ---- 3. switching the firewall while running --------------------------------

echo "== iptables <-> nftables while running"
have_ipt=
command -v iptables >/dev/null 2>&1 && iptables -V >/dev/null 2>&1 && have_ipt=1
if [ -z "$have_ipt" ]; then
    echo "  skip: iptables not usable"
else
    ipt_ours() {
        { iptables-save 2>/dev/null; ip6tables-save 2>/dev/null; } |
            grep -E 'NFQUEUE|opensnitch-filter'
    }
    switch_case() { # <label> <binary>
        nft flush ruleset
        iptables -F 2>/dev/null; iptables -t mangle -F 2>/dev/null
        write_config iptables
        set_sysfw "$upstream_daemon/data/system-fw.json"
        daemon_start "$2"
        if [ -n "$(ipt_ours)" ] && ! nft list table inet opensnitch >/dev/null 2>&1; then
            ok "$1: iptables rules, no nftables table"
        else
            fail "$1: iptables rules, no nftables table"
        fi
        write_config nftables
        sleep 1
        settle
        if [ -z "$(ipt_ours)" ] && nft list table inet opensnitch >/dev/null 2>&1; then
            ok "$1: iptables -> nftables leaves no iptables rule"
        else
            fail "$1: iptables -> nftables leaves no iptables rule"
            ipt_ours | sed 's/^/       /'
        fi
        write_config iptables
        sleep 1
        settle
        if [ -n "$(ipt_ours)" ] && ! nft list table inet opensnitch >/dev/null 2>&1; then
            ok "$1: nftables -> iptables leaves no nftables table"
        else
            fail "$1: nftables -> iptables leaves no nftables table"
            nft list ruleset | sed 's/^/       /'
        fi
        daemon_stop
        if [ -z "$(ipt_ours)" ] && [ -z "$(residue)" ]; then
            ok "$1: nothing left after stop"
        else
            fail "$1: nothing left after stop"
        fi
    }
    switch_case kisnitchd "$KISNITCHD"
    if [ -n "$upstream_16" ]; then
        echo "  skip opensnitchd $upstream_version: 1.6 doesn't reload the firewall"
    elif [ -n "$upstream_ok" ]; then
        switch_case "opensnitchd $upstream_version" "$OPENSNITCHD"
    fi
fi

# ---- 4. RELOAD_FW_RULES from a UI ---------------------------------------------

echo "== the UI: Subscribe and RELOAD_FW_RULES"
if ! python3 -W ignore -c "import grpc, grpc_tools" 2>/dev/null; then
    echo "  skip: python3 grpcio and grpc_tools not installed"
else
    mkdir -p "$work/pb" "$work/ctl"
    python3 -W ignore -m grpc_tools.protoc -I"$root/proto" --python_out="$work/pb" \
        --grpc_python_out="$work/pb" "$root/proto/ui.proto" 2>/dev/null
    ip link set lo up 2>/dev/null
    wait_log() { # <seconds> <pattern>
        n=$(($1 * 10))
        until grep -q "$2" "$work/ui.log" 2>/dev/null; do
            n=$((n - 1)); [ $n -le 0 ] && return 1
            sleep 0.1
        done
    }
    # the reply to notification <id>: "<code> <data>"
    reply_of() {
        python3 -c 'import json,sys
for l in open(sys.argv[1]):
    m = json.loads(l)
    if m.get("rpc") == "NotificationReply" and m["id"] == int(sys.argv[2]):
        print(m["code"], m["data"])' "$work/ui.log" "$1"
    }
    reload_case() { # <label> <binary> <saved file copy>
        nft flush ruleset
        rm -f "$work/ui.log" "$work/ui.sock"
        write_config nftables
        set_sysfw "$upstream_daemon/data/system-fw.json"
        python3 "$here/fake_ui.py" "$work/pb" "$work/ui.sock" "$work/ui.log" "$work/ctl" \
            >"$work/ui.err" 2>&1 &
        ui_pid=$!
        n=50; until [ -S "$work/ui.sock" ] || [ $n -le 0 ]; do n=$((n - 1)); sleep 0.1; done
        daemon_start "$2"
        if wait_log 15 '"event": "open"'; then
            ok "$1: connects to the UI"
        else
            fail "$1: connects to the UI"
        fi
        if python3 -c 'import json,sys
s = [json.loads(l) for l in open(sys.argv[1]) if "\"Subscribe\"" in l][-1]["sysfw"]
c = s["SystemRules"][-1]["Chains"]
assert s["Enabled"] and s["Version"] == 1 and len(c) == 12, s
r = [x for x in c if x["Name"] == "mangle_output"][0]["Rules"]
assert len(r) == 4 and all(len(x["UUID"]) == 36 for x in r), r' "$work/ui.log" 2>"$work/err"; then
            ok "$1: Subscribe carries system-fw.json (with UUIDs)"
        else
            fail "$1: Subscribe carries system-fw.json (with UUIDs)"
            sed 's/^/       /' "$work/err"
        fi

        echo "{\"type\": 5, \"sysfw\": \"$fixtures/drop-input.json\"}" > "$work/ctl/notify.json"
        if wait_log 10 '"rpc": "NotificationReply", "id": 101'; then
            r=$(reply_of 101)
            if [ "$r" = "0 " ]; then ok "$1: RELOAD_FW_RULES replies OK"
            else fail "$1: RELOAD_FW_RULES replies OK ($r)"; fi
        else
            fail "$1: RELOAD_FW_RULES replies"
        fi
        settle
        if ruleset | grep -q 'policy drop;' && ruleset | grep -q 'iifname "lo" accept'; then
            ok "$1: the new configuration is applied"
        else
            fail "$1: the new configuration is applied"
        fi
        saved=$work/system-fw.json
        [ -n "$upstream_16" ] && [ "$2" = "$OPENSNITCHD" ] && saved=$work/etc-fw.json
        cp "$saved" "$3"
        perm=$(stat -c %a "$saved")
        if [ "$perm" = 600 ]; then ok "$1: saved with mode 600"
        else fail "$1: saved with mode 600 ($perm)"; fi

        echo "{\"type\": 5, \"sysfw\": \"$fixtures/invalid-rule.json\"}" > "$work/ctl/notify.json"
        if wait_log 10 '"rpc": "NotificationReply", "id": 102'; then
            r=$(reply_of 102)
            case "$r" in
                "1 "*"(ks-invalid-rule),") ok "$1: an invalid rule is reported ($r)" ;;
                *) fail "$1: an invalid rule is reported ($r)" ;;
            esac
        else
            fail "$1: RELOAD_FW_RULES replies to an invalid rule"
        fi
        daemon_stop
        kill "$ui_pid" 2>/dev/null; wait "$ui_pid" 2>/dev/null
    }
    reload_case kisnitchd "$KISNITCHD" "$work/saved-ours.json"
    if [ -n "$upstream_ok" ]; then
        reload_case "opensnitchd $upstream_version" "$OPENSNITCHD" "$work/saved-theirs.json"
        if cmp -s "$work/saved-ours.json" "$work/saved-theirs.json"; then
            ok "the saved system-fw.json is byte for byte upstream's"
        else
            fail "the saved system-fw.json is byte for byte upstream's"
            diff -u "$work/saved-theirs.json" "$work/saved-ours.json" | head -40 | sed 's/^/       /'
        fi
    fi
fi

echo "sysfw: $pass passed, $failed failed"
[ "$failed" -eq 0 ]
