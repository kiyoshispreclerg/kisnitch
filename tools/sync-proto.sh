#!/bin/sh
# Copies upstream's proto/ui.proto into proto/ and, when protoc-c is
# available, regenerates common/pb/ (generated code: never edit it by hand).
set -eu
cd "$(dirname "$0")/.."

mkdir -p proto
cp upstream/proto/ui.proto proto/ui.proto
echo "copied upstream/proto/ui.proto ($(git -C upstream describe --tags))"

if command -v protoc-c >/dev/null 2>&1; then
    mkdir -p common/pb
    protoc-c --proto_path=proto --c_out=common/pb proto/ui.proto
    echo "regenerated common/pb/"
else
    echo "protoc-c not found: common/pb/ not regenerated (needed from phase 5)" >&2
fi
