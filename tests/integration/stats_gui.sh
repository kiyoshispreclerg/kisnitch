#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs tests/gui/test_stats_gui (the statistics window's dialogs and tasks,
# with the daemon's replies injected) on a virtual X server.
#
# STATS_GUI_TEST: path of the test binary (default build/tests/test_stats_gui).

set -u
here=$(cd "$(dirname "$0")" && pwd)
bin=${STATS_GUI_TEST:-$here/../../build/tests/test_stats_gui}
if ! command -v Xvfb >/dev/null 2>&1; then
    echo "SKIP (stats gui): Xvfb not found"
    exit 0
fi
if [ ! -x "$bin" ]; then
    echo "SKIP (stats gui): $bin not built"
    exit 0
fi
disp=$((120 + $$ % 60))
Xvfb ":$disp" -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 &
xp=$!
trap 'kill $xp 2>/dev/null' EXIT
i=0
until [ -e "/tmp/.X11-unix/X$disp" ]; do
    i=$((i + 1)); [ $i -gt 50 ] && { echo "FAIL: Xvfb didn't start"; exit 1; }
    sleep 0.1
done
ASAN_OPTIONS=fast_unwind_on_malloc=0 LSAN_OPTIONS="suppressions=$(cd "$(dirname "$0")/.." && pwd)/lsan.supp:print_suppressions=0" HOME=$(mktemp -d) DISPLAY=":$disp" "$bin"
