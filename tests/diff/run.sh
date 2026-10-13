#!/bin/sh
# Differential test (docs/PORTING.md, phase 1): evaluates tests/diff/corpus.json
# with upstream's Go rules package and with ours, and compares the results.
#
# Needs Go >= 1.21 (upstream asks for 1.23; newer Go downloads that toolchain
# by itself), the upstream/ submodule checked out, network access the first
# time (Go modules), and libnetfilter-queue-dev + pkg-config + a C compiler
# (upstream's netfilter package is cgo), and protobuf-compiler (protoc).
#
# Usage: tools are built under build/diff/; run from anywhere.
set -eu
cd "$(dirname "$0")/../.."

out=build/diff
mkdir -p "$out"

if [ ! -f upstream/daemon/rule/operator.go ]; then
    echo "upstream/ submodule missing: git submodule update --init" >&2
    exit 2
fi
command -v go >/dev/null || { echo "go not found" >&2; exit 2; }

# upstream doesn't commit the generated Go protobuf code, but its conman
# package (imported by rule) needs it. Generate it into the submodule tree
# (ignored by our repo) the way upstream/proto/Makefile does.
pbdir=upstream/daemon/ui/protocol
if [ ! -f "$pbdir/ui.pb.go" ]; then
    echo "== generating $pbdir/ui.pb.go"
    GOBIN="$(pwd)/$out/bin"; export GOBIN
    PATH="$GOBIN:$PATH"; export PATH
    command -v protoc >/dev/null || { echo "protoc not found (apt: protobuf-compiler)" >&2; exit 2; }
    command -v protoc-gen-go >/dev/null || go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
    command -v protoc-gen-go-grpc >/dev/null || go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
    (cd upstream/proto && protoc -I. ui.proto \
        --go_out=../daemon/ui/protocol/ --go-grpc_out=../daemon/ui/protocol/ \
        --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative)
fi

echo "== building the Go harness (upstream $(git -C upstream describe --tags 2>/dev/null || echo '?'))"
(cd tests/diff/go && go mod tidy >/dev/null && go build -o "../../../$out/diff-go" .)

echo "== building the C harness"
make -s "$out/ks_diff"

echo "== running"
"$out/diff-go" tests/diff/corpus.json "$out/go.txt"
"$out/ks_diff" tests/diff/corpus.json "$out/c.txt"

# Upstream panics on some type/operand combinations (e.g. a "network"
# operator on "dest.ip"); Kisnitch doesn't match instead. Count those apart.
awk '
    NR == FNR { go[$1] = substr($0, length($1) + 2); next }
    {
        id = $1; c = substr($0, length($1) + 2); total++
        if (!(id in go)) { printf "only in C: %s\n", $0; bad++; next }
        if (go[id] == c) { same++ }
        else if (go[id] == "panic" && c == "nomatch") { panics++ }
        else { printf "DIFF %s: go=%s c=%s\n", id, go[id], c; bad++ }
        delete go[id]
    }
    END {
        for (id in go) { printf "only in Go: %s\n", id; bad++ }
        printf "\n%d cases: %d identical, %d upstream panics (no match here), %d different\n",
               total, same, panics, bad
        exit bad > 0
    }
' "$out/go.txt" "$out/c.txt"
