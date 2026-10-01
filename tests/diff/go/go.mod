// Differential test harness: evaluates tests/diff/corpus.json with upstream's
// own rule package (from the upstream/ submodule). Not part of the build.
module kisnitch/diff

go 1.23.0

require github.com/evilsocket/opensnitch/daemon v0.0.0

replace github.com/evilsocket/opensnitch/daemon => ../../../upstream/daemon
