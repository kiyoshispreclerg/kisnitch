#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Desktop notifications (NOTIFY=1) against a fake notification daemon on a
# private D-Bus session. NOTIFY_TEST: the test binary (tests/gui/test_notify.c).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if ! command -v dbus-run-session >/dev/null 2>&1 ||
   ! python3 -c 'import gi; gi.require_version("Gio", "2.0")' 2>/dev/null; then
    echo "SKIP (notifications): dbus-run-session or python3-gi not found"
    exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dbus-run-session -- sh -c '
    python3 "$1/fake_notifyd.py" "$2/log" > "$2/ready" &
    pid=$!
    i=0
    until grep -q ready "$2/ready" 2>/dev/null; do
        i=$((i + 1)); [ $i -gt 100 ] && { echo "FAIL: the fake notification daemon did not start"; exit 1; }
        sleep 0.05
    done
    "$3" "$2/log"; rc=$?
    kill $pid
    exit $rc
' sh "$here" "$tmp" "$NOTIFY_TEST"
