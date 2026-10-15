#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Differential test of the rules editor: the same cases (gen_cases.py)
# through upstream's own dialog code (upstream_ruleseditor.py, upstream/ui
# at the pinned tag, Qt replaced by stand-ins) and through ui/rulegen.c
# (build/diff/ks_rules_diff). The rules, the forms and the messages must be
# the same, byte for byte.
#
# Needs the upstream/ submodule and python3 with protobuf, grpc_tools
# (to compile proto/ui.proto), python-slugify and unidecode.
#
#   KS_RULES_DIFF: path of ks_rules_diff (default build/diff/ks_rules_diff)
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$here/../../..
bin=${KS_RULES_DIFF:-$root/build/diff/ks_rules_diff}

if [ ! -f "$root/upstream/ui/opensnitch/dialogs/ruleseditor.py" ]; then
    echo "SKIP: upstream/ submodule not checked out"
    exit 0
fi
if ! python3 -c 'import google.protobuf, grpc_tools, slugify, unidecode' 2>/dev/null; then
    echo "SKIP: python3 needs protobuf, grpc_tools, slugify and unidecode"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 -W ignore -m grpc_tools.protoc -I"$root/upstream/proto" --python_out="$work" \
    "$root/upstream/proto/ui.proto" || exit 1
python3 "$here/gen_cases.py" > "$work/cases.jsonl" || exit 1
python3 -W ignore "$here/upstream_ruleseditor.py" "$root/upstream/ui" "$work" "$work/cases.jsonl" \
    "$work/upstream.jsonl" > /dev/null || { echo "FAIL: upstream side"; exit 1; }
"$bin" "$work/cases.jsonl" "$work/ours.jsonl" || { echo "FAIL: our side"; exit 1; }

n=$(wc -l < "$work/upstream.jsonl")
if ! diff -u "$work/upstream.jsonl" "$work/ours.jsonl" > "$work/diff"; then
    echo "FAIL: the rules editors disagree (- upstream, + ours):"
    head -n 40 "$work/diff"
    echo "($(grep -c '^-{' "$work/diff") of $n results differ)"
    # the cases behind the first differences
    exit 1
fi
echo "ok   $n rules editor results identical to upstream's"
