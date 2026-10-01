#!/bin/sh
# Lists upstream changes since the commit recorded in docs/UPSTREAM.md,
# grouped by area (docs/PORTING.md, section 7.2).
#
# Usage: tools/upstream-diff.sh [target-ref]   (default: upstream/ HEAD)
set -eu
cd "$(dirname "$0")/.."

base=$(sed -n 's/^Commit: *\([0-9a-f]\{7,\}\).*/\1/p' docs/UPSTREAM.md | head -n1)
[ -n "$base" ] || { echo "no 'Commit:' line in docs/UPSTREAM.md" >&2; exit 1; }
target=${1:-HEAD}

up() { git -C upstream "$@"; }

echo "upstream changes $(up describe --tags "$base") ($base) -> $(up describe --tags "$target")"
echo

for area in proto daemon/data daemon ui ebpf_prog; do
    # daemon/data has its own group.
    exclude=':!daemon/data'
    [ "$area" = daemon/data ] && exclude=':!nothing'
    files=$(up diff --name-only "$base" "$target" -- "$area" "$exclude")
    [ -n "$files" ] || continue
    case $area in
        proto)       title="proto/ (format change: top priority, run tools/sync-proto.sh)" ;;
        daemon/data) title="daemon/data/ (sample configs: run tools/sync-fixtures.sh)" ;;
        ebpf_prog)   title="ebpf_prog/ (run tools/sync-ebpf.sh and phase 9 tests)" ;;
        *)           title="$area/" ;;
    esac
    echo "== $title"
    up log --no-merges --format='   %h %s' "$base..$target" -- "$area" "$exclude"
    echo "$files" | sed 's/^/     /'
    echo
done

other=$(up diff --name-only "$base" "$target" -- . ':!proto' ':!daemon' ':!ui' ':!ebpf_prog')
if [ -n "$other" ]; then
    echo "== other"
    echo "$other" | sed 's/^/     /'
fi
