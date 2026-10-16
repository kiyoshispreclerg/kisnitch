#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Renders the PNG sizes of the Kisnitch icon from the SVG
# (data/icons/hicolor/scalable/apps/kisnitch.svg) with rsvg-convert.
# The PNGs are committed; run this after changing the SVG.

set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
svg=$here/data/icons/hicolor/scalable/apps/kisnitch.svg
for s in 16 22 24 32 48 64 128 256; do
    d=$here/data/icons/hicolor/${s}x${s}/apps
    mkdir -p "$d"
    rsvg-convert -w "$s" -h "$s" "$svg" -o "$d/kisnitch.png"
done
echo "icons written under data/icons/hicolor/"

# The tray's state icons (64x64, ui/res/tray-*.png), derived from the same SVG:
# enabled = no badge; alert = the SVG as is (amber badge); pause = no badge, a pause badge; off = no badge, grey and faded.
res=$here/ui/res
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
nobadge=$tmp/nobadge.svg
# the last three elements of the SVG are the badge
sed -e '/<circle cx="190" cy="70"/,/<circle cx="190" cy="80"/d' "$svg" > "$nobadge"
rsvg-convert -w 64 -h 64 "$nobadge" -o "$res/tray-enabled.png"
rsvg-convert -w 64 -h 64 "$svg" -o "$res/tray-alert.png"
sed -e 's|</svg>|<circle cx="190" cy="70" r="20" fill="#f59e0b" stroke="#0f172a" stroke-width="5"/><rect x="182" y="60" width="5" height="20" rx="1.5" fill="#0f172a"/><rect x="193" y="60" width="5" height="20" rx="1.5" fill="#0f172a"/></svg>|' \
    "$nobadge" > "$tmp/pause.svg"
rsvg-convert -w 64 -h 64 "$tmp/pause.svg" -o "$res/tray-pause.png"
rsvg-convert -w 64 -h 64 "$nobadge" -o "$tmp/off.png"
convert "$tmp/off.png" -colorspace Gray -channel A -evaluate multiply 0.55 +channel "$res/tray-off.png"
echo "tray icons written under ui/res/"
