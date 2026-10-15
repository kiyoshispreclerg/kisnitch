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
