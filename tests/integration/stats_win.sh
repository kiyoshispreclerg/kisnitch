#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The statistics window (phase 7) on a virtual X server: it opens when a
# second instance asks, shows a database of 100 000 events, and the UI
# stays responsive and small while it is on screen. No network involved.
#
# KISNITCH_GTK: path of the UI (default build/kisnitch-gtk).
# KS_SHOT_DIR: if set, screenshots are copied there.
# Needs Xvfb, xdotool, ImageMagick (import) and python3 with sqlite3.

set -u

here=$(cd "$(dirname "$0")" && pwd)
KISNITCH_GTK=${KISNITCH_GTK:-$here/../../build/kisnitch-gtk}
NEVENTS=${NEVENTS:-100000}

for tool in Xvfb xdotool python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP (stats window): $tool not found"
        exit 0
    fi
done
if [ ! -x "$KISNITCH_GTK" ]; then
    echo "SKIP (stats window): $KISNITCH_GTK not built"
    exit 0
fi

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL $1"; }

tmp=$(mktemp -d)
pids=""
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$tmp"
}
trap cleanup EXIT

export HOME=$tmp/home
export XDG_CONFIG_HOME=$HOME/.config
export XDG_RUNTIME_DIR=$tmp/run
mkdir -p "$XDG_CONFIG_HOME/opensnitch" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
cat > "$XDG_CONFIG_HOME/opensnitch/settings.conf" <<EOF
[database]
type=1
file=$tmp/ui.db
jrnl_wal=false

[statsDialog]
general_limit_results=4
EOF

disp=$((90 + $$ % 100))
Xvfb ":$disp" -screen 0 1400x900x24 >/dev/null 2>&1 &
pids="$pids $!"
export DISPLAY=":$disp"
sleep 1

sock=unix://$tmp/osui.sock
start_ui() {
    "$KISNITCH_GTK" --socket "$sock" >"$tmp/ui.log" 2>&1 &
    uipid=$!
    pids="$pids $uipid"
    i=0
    while [ $i -lt 50 ] && ! grep -q 'addr:' "$tmp/ui.log" 2>/dev/null; do
        sleep 0.1
        i=$((i + 1))
    done
}

# 1. first run creates the database file with its schema
start_ui
kill "$uipid"; wait "$uipid" 2>/dev/null
[ -f "$tmp/ui.db" ] && ok "the UI created its database file" || bad "no database file"

# 2. 100 000 events, as the daemon's Pings would have stored them
python3 - "$tmp/ui.db" "$NEVENTS" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1]); n = int(sys.argv[2])
rows = []
for i in range(n):
    rows.append(("2026-01-01 %02d:%02d:%02d.%06d" % (i // 3600 % 24, i // 60 % 60, i % 60, i % 1000000),
                 "unix:/local", "deny" if i % 3 == 0 else "allow", "tcp", "10.0.0.2", str(1024 + i % 60000),
                 "93.184.%d.%d" % (i // 256 % 256, i % 256), "host%d.example" % (i % 500), "443", "1000",
                 str(i % 5000), "/usr/bin/prog%d" % (i % 40), "arg", "/", "rule%d" % (i % 20)))
db.executemany("INSERT OR IGNORE INTO connections (time,node,action,protocol,src_ip,src_port,dst_ip,"
               "dst_host,dst_port,uid,pid,process,process_args,process_cwd,rule) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
db.executemany("INSERT OR REPLACE INTO hosts VALUES (?,?)", [("host%d.example" % i, i) for i in range(500)])
for i, (st, pr, fam) in enumerate((("10", "6", "2"), ("1", "6", "2"), ("7", "17", "10"), ("6", "6", "2"))):
    db.execute("INSERT INTO sockets (last_seen,node,src_port,src_ip,dst_ip,dst_port,proto,uid,inode,iface,family,state,"
               "cookies,rqueue,wqueue,expires,retrans,timer,proc_path,proc_comm,proc_pid) "
               "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               ("t", "unix:/local", str(1000 + i), "10.0.0.2", "1.1.1.%d" % i, "443", pr, "1000", str(5000 + i),
                "eth0", fam, st, "[1, 2]", "0", "0", "0", "0", "0", "/usr/bin/curl", "curl", str(100 + i)))
for n, (act, dur) in enumerate((("allow", "always"), ("deny", "5m"), ("reject", "always"))):
    db.execute("INSERT INTO rules (time,node,name,enabled,precedence,action,duration,operator_type,"
               "operator_sensitive,operator_operand,operator_data,description,nolog,created) "
               "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               ("t", "unix:/local", "rule%d" % n, "True", "False", act, dur, "simple", "False",
                "process.path", "/usr/bin/curl", "", "False", "2026-01-01 10:00:00"))
db.commit()
print(db.execute("select count(*) from connections").fetchone()[0])
PY

# 3. the window comes up on a second instance's request
start_ui
t0=$(date +%s.%N)
"$KISNITCH_GTK" --socket "$sock" >/dev/null 2>&1
win=$(xdotool search --sync --onlyvisible --name "Kisnitch Network Statistics" 2>/dev/null | head -1)
t1=$(date +%s.%N)
if [ -n "$win" ]; then
    ok "the statistics window opened ($(echo "$t1 - $t0" | bc 2>/dev/null || echo '?') s, $NEVENTS events)"
else
    bad "the statistics window did not open"
    cat "$tmp/ui.log"
fi

# 4. drive it: tabs, scrolling to the end of the table, and back
if [ -n "$win" ]; then
    xdotool windowfocus "$win" 2>/dev/null
    sleep 0.5
    if command -v import >/dev/null 2>&1; then
        import -window root "$tmp/events.png" 2>/dev/null
        [ -n "${KS_SHOT_DIR:-}" ] && cp "$tmp/events.png" "$KS_SHOT_DIR/stats-events.png"
    fi
    s0=$(date +%s.%N)
    xdotool mousemove 700 400 click 1 2>/dev/null
    xdotool key --delay 5 End 2>/dev/null
    sleep 0.5
    if command -v import >/dev/null 2>&1; then
        import -window root "$tmp/end.png" 2>/dev/null
        [ -n "${KS_SHOT_DIR:-}" ] && cp "$tmp/end.png" "$KS_SHOT_DIR/stats-end.png"
    fi
    xdotool key --delay 5 Prior Prior Prior Home 2>/dev/null
    for tab in 1 2 3 4 5 6 7 8 0; do
        xdotool key --delay 20 ctrl+Next 2>/dev/null
    done
    sleep 1
    s1=$(date +%s.%N)
    if kill -0 "$uipid" 2>/dev/null; then ok "the UI survived scrolling and tab changes"; else bad "the UI died"; fi
    # still answers its instance socket
    "$KISNITCH_GTK" --socket "$sock" >/dev/null 2>&1
    sleep 0.5
    n=$(grep -c 'asked to open the main window' "$tmp/ui.log")
    [ "$n" -ge 2 ] && ok "the UI is still responsive ($n open requests served)" || bad "the UI stopped answering"
    if command -v import >/dev/null 2>&1; then
        import -window root "$tmp/after.png" 2>/dev/null
        [ -n "${KS_SHOT_DIR:-}" ] && cp "$tmp/after.png" "$KS_SHOT_DIR/stats-after.png"
    fi
    rss=$(awk '/VmRSS/ {print $2}' /proc/$uipid/status)
    echo "  RSS with $NEVENTS events and the window open: $((rss / 1024)) MB"
    [ "$rss" -lt 150000 ] && ok "RSS under 150 MB" || bad "RSS is $((rss / 1024)) MB"
fi

# 4b. the Netstat tab shows the sockets table with names for the numbers
if [ -n "$win" ]; then
    xdotool mousemove 480 48 click 1 2>/dev/null   # Netstat (the last tab)
    sleep 0.8
    if command -v import >/dev/null 2>&1; then
        import -window root "$tmp/netstat.png" 2>/dev/null
        [ -n "${KS_SHOT_DIR:-}" ] && cp "$tmp/netstat.png" "$KS_SHOT_DIR/stats-netstat.png"
    fi
    if kill -0 "$uipid" 2>/dev/null; then ok "the Netstat tab opens"; else bad "the UI died on the Netstat tab"; fi
    xdotool mousemove 31 48 click 1 2>/dev/null    # back to Events
    sleep 0.5
fi

# 5. Ctrl+C on the events table puts the selected rows on the clipboard as CSV
if [ -n "$win" ] && command -v xsel >/dev/null 2>&1; then
    xdotool key --delay 20 Home 2>/dev/null
    xdotool mousemove 300 106 click 1 2>/dev/null
    sleep 0.3
    xdotool key ctrl+c 2>/dev/null
    sleep 0.3
    clip=$(xsel -b -o 2>/dev/null </dev/null | head -1 | tr -d '\r')
    case "$clip" in
        2026-01-01\ *:*.*,unix:/local,allow,*|2026-01-01\ *:*.*,unix:/local,deny,*) ok "Ctrl+C copies the selected event as CSV" ;;
        *) bad "Ctrl+C: clipboard is '$clip'" ;;
    esac

    # 6. the events menu: Details opens the connection's window
    xdotool mousemove 300 106 click 3 2>/dev/null
    sleep 0.4
    xdotool key Down Return 2>/dev/null
    sleep 0.6
    dw=$(xdotool search --onlyvisible --name "Connection details" 2>/dev/null | head -1)
    if [ -n "$dw" ]; then
        ok "the events menu opens the connection details"
        xdotool windowclose "$dw" 2>/dev/null   # there is no window manager to close it
        sleep 0.3
    else
        bad "no connection details window"
    fi
fi

# 7. the rules menu: Duplicate adds a rule to the table
if [ -n "$win" ]; then
    xdotool mousemove 131 48 click 1 2>/dev/null   # the Rules tab
    sleep 0.6
    xdotool mousemove 300 140 click 1 2>/dev/null  # first rule
    sleep 0.2
    xdotool mousemove 300 140 click 3 2>/dev/null
    sleep 0.5
    # Action, Duration, Disable, Duplicate
    xdotool key Down Down Down Down Return 2>/dev/null
    sleep 1
    dups=$(python3 -c "
import sqlite3, sys
print(sqlite3.connect('$tmp/ui.db').execute(\"select count(*) from rules where name like '%-duplicated-%'\").fetchone()[0])")
    [ "$dups" = "1" ] && ok "the rules menu duplicated a rule" || bad "rules after Duplicate: $dups duplicated"
fi

echo "stats window: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
