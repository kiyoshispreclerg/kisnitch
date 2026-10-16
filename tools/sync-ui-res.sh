#!/bin/sh
# Copies the upstream UI resources the GTK UI embeds into ui/res/ (network_aliases.json;
# the tray icons are ours, see tools/gen-icons.sh). Run after moving the upstream/ submodule to
# a new tag; the build embeds them with tools/bin2c.c.
set -eu
cd "$(dirname "$0")/.."

dst=ui/res
mkdir -p "$dst"
cp upstream/ui/opensnitch/utils/network_aliases/network_aliases.json "$dst/network_aliases.json"
echo "ui/opensnitch/utils/network_aliases/network_aliases.json -> $dst/network_aliases.json"
printf '%s\n' "$(git -C upstream describe --tags) $(git -C upstream rev-parse HEAD)" > "$dst/VERSION"
