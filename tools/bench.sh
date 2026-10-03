#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Measures kisnitchd's memory (RSS) idle and under a load of new TCP
# connections, inside a network namespace (never the host's network).
# Results go to docs/BENCH.md by hand.
#
#   tools/bench.sh [rate per second] [seconds]     (default: 1000 10)
#
# KISNITCHD: path of the daemon (default: build/kisnitchd). As root it uses
# `unshare -n`, otherwise `unshare -Urn`. Needs python3.

set -u
here=$(cd "$(dirname "$0")" && pwd)
KISNITCHD=${KISNITCHD:-$here/../build/kisnitchd}
RATE=${1:-1000}
SECS=${2:-10}

if [ -z "${KS_TEST_IN_NETNS:-}" ]; then
    if [ "$(id -u)" -eq 0 ]; then ns="unshare -n"; else ns="unshare -Urn"; fi
    KS_TEST_IN_NETNS=1 KISNITCHD="$KISNITCHD" exec $ns sh "$0" "$@"
fi

ip link set lo up
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT
mkdir -p "$work/rules"
py=$(readlink -f "$(command -v python3)")

cat > "$work/config.json" <<EOF
{
    "Server": {"Address": "unix:///tmp/kisnitch-bench-none.sock", "LogFile": ""},
    "DefaultAction": "deny", "DefaultDuration": "once", "InterceptUnknown": false,
    "ProcMonitorMethod": "proc", "LogLevel": 2, "LogUTC": true, "LogMicro": false,
    "Firewall": "nftables",
    "FwOptions": {"ConfigPath": "", "MonitorInterval": "15s", "QueueBypass": true},
    "Rules": {"Path": "$work/rules", "EnableChecksums": false},
    "Internal": {"GCPercent": 100, "FlushConnsOnStart": true}
}
EOF
cat > "$work/rules/allow-python.json" <<EOF
{"created": "2026-01-01T00:00:00Z", "updated": "2026-01-01T00:00:00Z",
 "name": "allow-python", "description": "", "enabled": true, "precedence": false,
 "nolog": false, "action": "allow", "duration": "always",
 "operator": {"type": "simple", "operand": "process.path", "sensitive": false,
              "data": "$py", "list": []}}
EOF

rss() { awk '/^VmRSS/ {print $2}' "/proc/$1/status"; }
hwm() { awk '/^VmHWM/ {print $2}' "/proc/$1/status"; }
cpu() { awk '{print $14 + $15}' "/proc/$1/stat"; } # utime + stime, in ticks

"$KISNITCHD" -config-file "$work/config.json" -log-file "$work/daemon.log" &
pid=$!
i=0
until grep -q "Running on netfilter queue" "$work/daemon.log" 2>/dev/null; do
    i=$((i + 1)); [ $i -gt 100 ] && { echo "daemon didn't start"; exit 1; }
    sleep 0.1
done
sleep 2
idle=$(rss $pid)

# Server: accepts and closes. Client: RATE new connections per second,
# each one a SYN through the queue, for SECS seconds.
python3 - "$RATE" "$SECS" > "$work/load.out" <<'EOF' &
import socket, sys, threading, time
rate, secs = int(sys.argv[1]), int(sys.argv[2])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(4096)
port = srv.getsockname()[1]
def serve():
    while True:
        c, _ = srv.accept(); c.close()
threading.Thread(target=serve, daemon=True).start()
done = failed = 0
start = time.monotonic()
while time.monotonic() - start < secs:
    t0 = time.monotonic()
    for _ in range(rate // 100):
        s = socket.socket(); s.settimeout(2)
        try:
            s.connect(("127.0.0.1", port)); done += 1
        except OSError:
            failed += 1
        s.close()
    left = 0.01 - (time.monotonic() - t0)
    if left > 0:
        time.sleep(left)
elapsed = time.monotonic() - start
print(f"{done} {failed} {elapsed:.2f}")
EOF
load=$!

cpu0=$(cpu $pid)
peak=0
while kill -0 $load 2>/dev/null; do
    r=$(rss $pid); [ "$r" -gt "$peak" ] && peak=$r
    sleep 0.2
done
cpu1=$(cpu $pid)
read -r done failed elapsed < "$work/load.out"
after=$(rss $pid)
sleep 3
settled=$(rss $pid)
ticks=$(getconf CLK_TCK)

echo "kisnitchd $("$KISNITCHD" -version), $(uname -r), $(nproc) CPUs"
echo "RSS idle:                ${idle} KiB"
echo "load: target ${RATE}/s for ${SECS}s -> $done connections ($failed failed) in ${elapsed}s" \
     "= $(awk "BEGIN {printf \"%.0f\", $done / $elapsed}")/s"
echo "RSS peak under load:     ${peak} KiB (VmHWM $(hwm $pid) KiB)"
echo "RSS right after / +3s:   ${after} / ${settled} KiB"
echo "daemon CPU during load:  $(awk "BEGIN {printf \"%.0f\", 100 * ($cpu1 - $cpu0) / $ticks / $elapsed}")% of one core"
kill -TERM $pid
wait $pid
