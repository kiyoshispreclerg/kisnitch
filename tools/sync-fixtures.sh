#!/bin/sh
# Copies the upstream sample files the tests use into tests/fixtures/upstream/.
# Run after moving the upstream/ submodule to a new tag, then re-run the tests.
set -eu
cd "$(dirname "$0")/.."

dst=tests/fixtures/upstream
mkdir -p "$dst"

# <upstream path> <fixture name>
while read -r src name; do
    [ -n "$src" ] || continue
    cp "upstream/$src" "$dst/$name"
    echo "$src -> $dst/$name"
done <<LIST
daemon/data/default-config.json            default-config.json
daemon/ui/testdata/default-config.json     ui-testdata-default-config.json
daemon/ui/testdata/config-invalid-procmon.json ui-testdata-config-invalid-procmon.json
daemon/data/network_aliases.json           network_aliases.json
LIST

# Whole directories.
rm -rf "$dst/rules"
cp -r upstream/daemon/rule/testdata "$dst/rules"
echo "daemon/rule/testdata/ -> $dst/rules/"

printf '%s\n' "$(git -C upstream describe --tags) $(git -C upstream rev-parse HEAD)" > "$dst/VERSION"
