# Kisnitch

[English](README.md) | **[Português (Brasil)](README.pt-BR.md)**

A lightweight version of [OpenSnitch](https://github.com/evilsocket/opensnitch),
the Linux application firewall, rewritten in C11 with a GTK2 interface.

The goal is to be a drop-in replacement: same configuration and rule files,
and the same gRPC protocol between daemon and UI. Kisnitch's daemon works with
the original UI and vice versa.

> **Status:** version 0.1.0, phase 7 of 11 complete. The daemon intercepts
> connections (nfqueue + nftables), applies rules, tracks DNS and talks to
> both the original OpenSnitch UI and our own. The GTK2 UI (`kisnitch-gtk`)
> is complete: permission popup, tray icon, statistics window, rules editor
> and preferences. Not done yet: the system firewall (`system-fw.json`, phase
> 8), the eBPF process monitor (phase 9, optional), and the remainder (audit
> monitor, tasks, TLS between daemon and UI, i18n; phase 10). The full plan is
> in [docs/PORTING.md](docs/PORTING.md).

## Build and test

On Debian/Devuan/Ubuntu:

```sh
sudo apt install build-essential pkg-config libpcre2-dev \
    libnetfilter-queue-dev libnftnl-dev libmnl-dev \
    libnghttp2-dev libprotobuf-c-dev libgtk2.0-dev
make            # build/kisnitchd and build/kisnitch-gtk
make test       # unit tests (no root, no network)
make asan       # the same tests with AddressSanitizer + UBSan
```

Integration tests (need `nftables`, `curl` and `python3`; the tests with the
fake UI also need `python3-grpcio` and `python3-grpc-tools`, and those for our
UI need `xvfb` and `xdotool`; each part is skipped if its requirements are
missing). They run in their own network namespace and do not touch the
machine's network:

```sh
sudo make test-integration   # or without sudo, if the kernel allows user namespaces
```

Optional: `valgrind` (`make valgrind`), `cppcheck` (`make lint`) and `clang`
(`make fuzz-run`). Only whoever changes `proto/ui.proto` needs
`protobuf-c-compiler` (`tools/sync-proto.sh` regenerates `common/pb/`).

Nothing is installed on the system: everything stays in `build/`. The daemon
uses the same files as OpenSnitch (`/etc/opensnitchd/default-config.json` and
`/etc/opensnitchd/rules/`) and needs root. Stop `opensnitchd` first, because
both use the same queue and the same nftables table:

```sh
sudo ./build/kisnitchd -debug -log-file /dev/stdout
```

Ctrl+C removes the interception rules. To try it without touching the
machine's network, run it inside `sudo unshare -n` (which is what the
integration tests do).

### With the original UI

The OpenSnitch UI (`opensnitch-ui`) is the server: it listens on
`unix:///tmp/osui.sock` (the default config's `Server.Address`) and the daemon
connects to it. With the UI open in the graphical session:

```sh
sudo systemctl stop opensnitch     # or the equivalent for your init
sudo ./build/kisnitchd -debug -log-file /dev/stdout
```

The log shows "Connected to the UI service on ..." and "Start receiving
notifications"; from then on, connections without a rule open the UI's popup,
and what you choose there becomes a rule in `/etc/opensnitchd/rules/` (if the
duration is "always"). To point at another socket: `-ui-socket unix:///path`.
TLS authentication between daemon and UI does not exist yet (phase 10).

### The UI (`kisnitch-gtk`)

It replaces `opensnitch-ui`: it listens on the same address
(`unix:///tmp/osui.sock`, or `global/server_address` from
`~/.config/opensnitch/settings.conf`, the same file as the original UI) and
shows the popup for each connection without a rule. Close the original UI
first (both use the same socket and the same single-instance lock):

```sh
./build/kisnitch-gtk                       # or --socket unix:///other/path
```

It works with the original `opensnitchd` and with `kisnitchd`. The tray
menu toggles interception and autostart. The statistics window, the rules
editor and the preferences window are the same ones the original UI offers and
read and write the same `settings.conf` and use a SQLite schema compatible with the original.

### Differential test (optional)

Compares the rules engine with OpenSnitch's own Go code, over the corpus in
`tests/diff/corpus.json`. It runs in the CI `diff` job; to run it locally:

```sh
git submodule update --init          # upstream code in upstream/
sudo apt install golang-go libnetfilter-queue-dev
make diff
```

It needs Go 1.21 or newer (with network access the first time, to download
the 1.23 toolchain that upstream requires and the Go modules).

The UI popup has its own: `make diff-ui` runs the same cases through the
original popup's Python code (with Qt replaced) and through ours. It needs the
submodule and `python3-protobuf python3-grpc-tools python3-slugify
python3-unidecode`.

## Credits and license

Kisnitch is a derivative work of OpenSnitch, created by Simone Margaritelli
(evilsocket) and maintained by Gustavo Iñiguez Goia and contributors. Files
translated from the original code keep their copyright notices.

Distributed under the [GNU GPL v3 or later](LICENSE), the same license as
OpenSnitch. cJSON, in `common/vendor/cjson/`, is distributed under the MIT
license.
