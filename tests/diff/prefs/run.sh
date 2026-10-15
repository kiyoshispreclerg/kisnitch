#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Differential test of the preferences' node configuration: the same cases
# (gen_cases.py) through upstream's own dialog code (upstream_prefs.py,
# upstream/ui at the pinned tag, Qt replaced by stand-ins) and through
# ui/prefs_node.c (build/diff/ks_prefs_diff). The forms and the
# configurations must be the same, byte for byte.
#
# Needs the upstream/ submodule and python3 with protobuf, grpc_tools and
# grpc (opensnitch.auth imports it).
#
#   KS_PREFS_DIFF: path of ks_prefs_diff (default build/diff/ks_prefs_diff)
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$here/../../..
bin=${KS_PREFS_DIFF:-$root/build/diff/ks_prefs_diff}

if [ ! -f "$root/upstream/ui/opensnitch/dialogs/preferences.py" ]; then
    echo "SKIP: upstream/ submodule not checked out"
    exit 0
fi
if ! python3 -c 'import google.protobuf, grpc_tools, grpc' 2>/dev/null; then
    echo "SKIP: python3 needs protobuf, grpc_tools and grpc"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 -W ignore -m grpc_tools.protoc -I"$root/upstream/proto" --python_out="$work" \
    "$root/upstream/proto/ui.proto" || exit 1
python3 "$here/gen_cases.py" > "$work/cases.jsonl" || exit 1
python3 -W ignore "$here/upstream_prefs.py" "$root/upstream/ui" "$work" "$work/cases.jsonl" \
    "$work/upstream.jsonl" > /dev/null || { echo "FAIL: upstream side"; exit 1; }
"$bin" "$work/cases.jsonl" "$work/ours.jsonl" || { echo "FAIL: our side"; exit 1; }

n=$(wc -l < "$work/upstream.jsonl")
if ! diff -u "$work/upstream.jsonl" "$work/ours.jsonl" > "$work/diff"; then
    echo "FAIL: the preferences disagree (- upstream, + ours):"
    head -n 30 "$work/diff" | cut -c1-600
    echo "($(grep -c '^-{' "$work/diff") of $n results differ)"
    exit 1
fi
echo "ok   $n preferences results identical to upstream's"
