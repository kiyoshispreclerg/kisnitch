#!/bin/sh
# Copies the upstream UI resources the GTK UI embeds into ui/res/ (tray
# icons, network_aliases.json). Run after moving the upstream/ submodule to
# a new tag; the build embeds them with tools/bin2c.c.
set -eu
cd "$(dirname "$0")/.."

dst=ui/res
mkdir -p "$dst"
for f in icon-off.png icon-white.png icon-pause.png icon-red.png icon-alert.png; do
    cp "upstream/ui/opensnitch/res/$f" "$dst/$f"
    echo "ui/opensnitch/res/$f -> $dst/$f"
done
cp upstream/ui/opensnitch/utils/network_aliases/network_aliases.json "$dst/network_aliases.json"
echo "ui/opensnitch/utils/network_aliases/network_aliases.json -> $dst/network_aliases.json"
printf '%s\n' "$(git -C upstream describe --tags) $(git -C upstream rev-parse HEAD)" > "$dst/VERSION"
