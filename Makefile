include config.mk

BUILD ?= build

COMMON_SRC = common/log.c \
             common/arena.c \
             common/json_util.c \
             common/json_schema.c \
             common/unicode.c \
             common/duration.c \
             common/netaddr.c \
             common/strset.c \
             common/hash.c \
             common/strmap.c \
             common/grpc/grpc.c \
             common/grpc/tls.c \
             common/pb_util.c \
             common/sysfw.c
# Third-party and generated code: built with the base warnings only.
VENDOR_SRC = common/vendor/cjson/cJSON.c \
             common/pb/ui.pb-c.c
# Everything in the daemon except main.c goes into a static lib so the unit
# tests can link against it.
DAEMON_LIB_SRC = daemon/config.c \
                 daemon/conn.c \
                 daemon/dns/cache.c \
                 daemon/dns/parse.c \
                 daemon/dns/resolved.c \
                 daemon/evloop.c \
                 daemon/fw/fw.c \
                 daemon/fw/iptables.c \
                 daemon/fw/nft.c \
                 daemon/fw/nft_exprs.c \
                 daemon/fw/nft_sys.c \
                 daemon/fw/sysfw.c \
                 daemon/intercept.c \
                 daemon/loggers.c \
                 daemon/logformats.c \
                 daemon/netstat.c \
                 daemon/sockdiag.c \
                 daemon/procmon/audit.c \
                 daemon/procmon/cache.c \
                 daemon/procmon/events.c \
                 daemon/procmon/process.c \
                 daemon/procmon/procmon.c \
                 daemon/protocol.c \
                 daemon/queue.c \
                 daemon/stats.c \
                 daemon/tasks/downloader.c \
                 daemon/tasks/iocscanner.c \
                 daemon/tasks/load.c \
                 daemon/tasks/looper.c \
                 daemon/tasks/nodemon.c \
                 daemon/tasks/pidmon.c \
                 daemon/tasks/scheduler.c \
                 daemon/tasks/sockmon.c \
                 daemon/tasks/tasks.c \
                 daemon/uiclient.c \
                 daemon/rules/aliases.c \
                 daemon/rules/lists.c \
                 daemon/rules/loader.c \
                 daemon/rules/regex.c \
                 daemon/rules/rule.c
DAEMON_MAIN    = daemon/main.c
# The UI without widgets (GLib only): what the unit tests link.
UI_LIB_SRC = ui/db.c \
             ui/fwrules.c \
             ui/fwsimple.c \
             ui/highlight.c \
             ui/i18n.c \
             ui/desktop.c \
             ui/nodeinfo.c \
             ui/netstat.c \
             ui/nodes.c \
             ui/procinfo.c \
             ui/prefs_node.c \
             ui/prompt_rule.c \
             ui/qmodel.c \
             ui/pycsv.c \
             ui/pyjson.c \
             ui/rulegen.c \
             ui/rulesdb.c \
             ui/rulesops.c \
             ui/server.c \
             ui/service.c \
             ui/statsdb.c \
             ui/settings.c \
             ui/slug.c \
             ui/statsq.c
UI_GTK_SRC = ui/main.c \
             ui/stats_fw.c \
             ui/fw_dialog.c \
             ui/fw_rule_dialog.c \
             ui/fw_simple.c \
             ui/notify.c \
             ui/prompt.c \
             ui/rules_editor.c \
             ui/prefs.c \
             ui/qstore.c \
             ui/stats_menu.c \
             ui/stats_netstat.c \
             ui/stats_proc.c \
             ui/stats_node.c \
             ui/stats_win.c \
             ui/tray.c
UI_RES     = ui/res/network_aliases.json \
             data/icons/hicolor/128x128/apps/kisnitch.png \
             ui/res/tray-off.png \
             ui/res/tray-enabled.png \
             ui/res/tray-pause.png \
             ui/res/tray-alert.png

UNIT_TESTS = $(patsubst tests/unit/%.c,$(BUILD)/tests/%,$(filter-out tests/unit/test_ui_%,$(wildcard tests/unit/test_*.c)))
UI_TESTS   = $(patsubst tests/unit/%.c,$(BUILD)/tests/%,$(wildcard tests/unit/test_ui_*.c))
INTEGRATION_TESTS = $(patsubst tests/integration/%.c,$(BUILD)/itests/%,$(wildcard tests/integration/test_*.c))
FUZZERS    = $(patsubst tests/fuzz/%.c,$(BUILD)/fuzz/%,$(wildcard tests/fuzz/fuzz_*.c))
UI_FUZZERS = $(filter $(BUILD)/fuzz/fuzz_ui_%,$(FUZZERS))

ALL_CFLAGS  = $(STDFLAGS) $(OPTFLAGS) $(SANFLAGS) $(CFLAGS)
ALL_LDFLAGS = $(SANFLAGS) $(LDFLAGS)

LIBCOMMON = $(BUILD)/libcommon.a
LIBDAEMON = $(BUILD)/libdaemon.a
LIBUI     = $(BUILD)/libui.a

# ---- translations (po/*.po, from the upstream .ts: tools/update-po.sh) ------
# One kisnitch.mo per language under $(BUILD)/locale/<lang>/LC_MESSAGES/, the
# layout `make install` copies to $(DATADIR)/locale and KS_LOCALEDIR points
# at to try them from the build tree. Without msgfmt (gettext) the UI is
# built untranslated.
PO_LANGS = $(patsubst po/%.po,%,$(wildcard po/*.po))
HAVE_MSGFMT := $(shell command -v msgfmt 2>/dev/null)
ifneq ($(HAVE_MSGFMT),)
MOFILES = $(patsubst %,$(BUILD)/locale/%/LC_MESSAGES/kisnitch.mo,$(PO_LANGS))
endif

$(BUILD)/locale/%/LC_MESSAGES/kisnitch.mo: po/%.po
	@mkdir -p $(@D)
	msgfmt --check-format --check-header -o $@ $<

# i18n.o has the install path of the catalogs inside; rebuild it when DATADIR changes
$(BUILD)/ui/.datadir: FORCE
	@mkdir -p $(@D)
	@echo '$(DATADIR)' | cmp -s - $@ || echo '$(DATADIR)' > $@

$(BUILD)/ui/i18n.o: $(BUILD)/ui/.datadir
$(BUILD)/ui/i18n.o: CPPFLAGS += -DKS_LOCALEDIR='"$(DATADIR)/locale"'

FORCE:
.PHONY: FORCE

.PHONY: all test asan valgrind lint fuzz fuzz-run diff diff-ui ui-checklist clean test-integration install install-data install-mo install-service install-sysv uninstall

all: $(BUILD)/kisnitchd $(BUILD)/kisnitch-gtk $(MOFILES)

$(BUILD)/kisnitchd: $(BUILD)/$(DAEMON_MAIN:.c=.o) $(LIBDAEMON) $(LIBCOMMON)
	$(CC) $(ALL_LDFLAGS) -o $@ $^ $(LDLIBS)

$(LIBCOMMON): $(patsubst %.c,$(BUILD)/%.o,$(COMMON_SRC) $(VENDOR_SRC))
	$(AR) rcs $@ $^

$(LIBDAEMON): $(patsubst %.c,$(BUILD)/%.o,$(DAEMON_LIB_SRC))
	$(AR) rcs $@ $^

# ---- UI -------------------------------------------------------------------

$(BUILD)/kisnitch-gtk: $(patsubst %.c,$(BUILD)/%.o,$(UI_GTK_SRC)) $(LIBUI) $(LIBCOMMON)
	$(CC) $(ALL_LDFLAGS) -o $@ $^ $(LDLIBS) $(UI_LIBS) $(GTK_LIBS)

$(LIBUI): $(patsubst %.c,$(BUILD)/%.o,$(UI_LIB_SRC)) $(BUILD)/ui/res.o
	$(AR) rcs $@ $^

$(BUILD)/ui/%.o: ui/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(UI_CFLAGS) $(GTK_CFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP -c -o $@ $<

# The resources, as C arrays (ks_res_<file name>, see ui/res.h).
$(BUILD)/tools/bin2c: tools/bin2c.c
	@mkdir -p $(@D)
	$(CC) -O1 -o $@ $<

$(BUILD)/ui/res.c: $(UI_RES) $(BUILD)/tools/bin2c
	@mkdir -p $(@D)
	@rm -f $@.tmp
	@for f in $(UI_RES); do \
		n=ks_res_$$(basename $$f | tr '.-' '__'); \
		$(BUILD)/tools/bin2c $$n $$f >> $@.tmp || exit 1; \
	done
	@mv $@.tmp $@

$(BUILD)/ui/res.o: $(BUILD)/ui/res.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

$(BUILD)/common/vendor/%.o: common/vendor/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ALL_CFLAGS) $(VENDOR_WARNFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/common/pb/%.o: common/pb/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ALL_CFLAGS) $(VENDOR_WARNFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP -c -o $@ $<

# ---- tests ----------------------------------------------------------------

TEST_CPPFLAGS = -DKS_FIXTURES_DIR='"$(CURDIR)/tests/fixtures"' \
                -DKS_TEST_LOCALEDIR='"$(abspath $(BUILD))/locale"'

$(BUILD)/tests/%: tests/unit/%.c tests/harness.h $(LIBDAEMON) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(TEST_CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP \
		$(ALL_LDFLAGS) -o $@ $< $(LIBDAEMON) $(LIBCOMMON) $(LDLIBS)

$(BUILD)/tests/test_ui_%: tests/unit/test_ui_%.c tests/harness.h $(LIBUI) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(UI_CFLAGS) $(TEST_CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP \
		$(ALL_LDFLAGS) -o $@ $< $(LIBUI) $(LIBCOMMON) $(LDLIBS) $(UI_LIBS)

test: all $(UNIT_TESTS) $(UI_TESTS)
	@fail=0; for t in $(UNIT_TESTS) $(UI_TESTS); do \
		$$t || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "*** unit tests FAILED"; exit 1; fi; \
	echo "*** all unit tests passed"

asan:
	$(MAKE) BUILD=$(BUILD)/asan SANITIZE=1 test

# ---- installation (PREFIX and DESTDIR are respected) ------------------------
# `install-data` is what makes the UI show up in the launchers of the desktops:
# the .desktop file, the icon in the hicolor theme and the AppStream metadata.

ICON_SIZES = 16x16 22x22 24x24 32x32 48x48 64x64 128x128 256x256
DATADIR   ?= $(PREFIX)/share

install-data:
	install -Dm644 data/kisnitch.desktop $(DESTDIR)$(DATADIR)/applications/kisnitch.desktop
	install -Dm644 data/io.github.kisnitch.metainfo.xml \
		$(DESTDIR)$(DATADIR)/metainfo/io.github.kisnitch.metainfo.xml
	install -Dm644 data/icons/hicolor/scalable/apps/kisnitch.svg \
		$(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/kisnitch.svg
	@for s in $(ICON_SIZES); do \
		[ -f data/icons/hicolor/$$s/apps/kisnitch.png ] || continue; \
		install -Dm644 data/icons/hicolor/$$s/apps/kisnitch.png \
			$(DESTDIR)$(DATADIR)/icons/hicolor/$$s/apps/kisnitch.png || exit 1; \
	done
	@if [ -z "$(DESTDIR)" ]; then \
		gtk-update-icon-cache -q -t -f $(DATADIR)/icons/hicolor 2>/dev/null || true; \
		update-desktop-database -q $(DATADIR)/applications 2>/dev/null || true; \
	fi

install-mo:
	@for l in $(PO_LANGS); do \
		[ -f $(BUILD)/locale/$$l/LC_MESSAGES/kisnitch.mo ] || continue; \
		install -Dm644 $(BUILD)/locale/$$l/LC_MESSAGES/kisnitch.mo \
			$(DESTDIR)$(DATADIR)/locale/$$l/LC_MESSAGES/kisnitch.mo || exit 1; \
	done

# The systemd unit and the default /etc/opensnitchd files (the package's
# postinst copies those that are missing: the files of an existing OpenSnitch
# install are never touched). The XDG autostart entry starts the GUI at login.
install-service:
	install -Dm644 packaging/systemd/kisnitch.service $(DESTDIR)$(SYSTEMDDIR)/kisnitch.service
	install -Dm644 data/defaults/default-config.json data/defaults/system-fw.json \
		data/defaults/network_aliases.json -t $(DESTDIR)$(DATADIR)/kisnitch/defaults
	install -Dm644 data/defaults/rules/*.json -t $(DESTDIR)$(DATADIR)/kisnitch/defaults/rules
	install -Dm644 data/defaults/tasks/tasks.json -t $(DESTDIR)$(DATADIR)/kisnitch/defaults/tasks
	install -Dm644 data/kisnitch.desktop $(DESTDIR)$(SYSCONFDIR)/xdg/autostart/kisnitch.desktop

# For systems without systemd (Devuan): the init script and the log rotation.
install-sysv:
	install -Dm755 packaging/sysvinit/kisnitch $(DESTDIR)$(SYSCONFDIR)/init.d/kisnitch
	install -Dm644 packaging/logrotate/kisnitch $(DESTDIR)$(SYSCONFDIR)/logrotate.d/kisnitch

install: all install-data install-mo install-service
	install -Dm755 $(BUILD)/kisnitchd $(DESTDIR)$(SBINDIR)/kisnitchd
	install -Dm755 $(BUILD)/kisnitch-gtk $(DESTDIR)$(BINDIR)/kisnitch-gtk

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/kisnitchd $(DESTDIR)$(BINDIR)/kisnitch-gtk
	rm -f $(DESTDIR)$(DATADIR)/applications/kisnitch.desktop
	rm -f $(DESTDIR)$(DATADIR)/metainfo/io.github.kisnitch.metainfo.xml
	rm -f $(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/kisnitch.svg
	@for s in $(ICON_SIZES); do rm -f $(DESTDIR)$(DATADIR)/icons/hicolor/$$s/apps/kisnitch.png; done
	rm -f $(DESTDIR)$(SYSTEMDDIR)/kisnitch.service $(DESTDIR)$(SYSCONFDIR)/xdg/autostart/kisnitch.desktop
	rm -rf $(DESTDIR)$(DATADIR)/kisnitch
	rm -f $(DESTDIR)$(SYSCONFDIR)/init.d/kisnitch $(DESTDIR)$(SYSCONFDIR)/logrotate.d/kisnitch
	@for l in $(PO_LANGS); do rm -f $(DESTDIR)$(DATADIR)/locale/$$l/LC_MESSAGES/kisnitch.mo; done

# ---- tests of the windows (they need a display: tests/integration/stats_gui.sh) ---

GUI_OBJS = $(patsubst %.c,$(BUILD)/%.o,$(filter-out ui/main.c,$(UI_GTK_SRC)))

$(BUILD)/tests/test_stats_gui: tests/gui/test_stats_gui.c tests/harness.h $(GUI_OBJS) $(LIBUI) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(UI_CFLAGS) $(GTK_CFLAGS) $(TEST_CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) \
		-MMD -MP $(ALL_LDFLAGS) -o $@ $< $(GUI_OBJS) $(LIBUI) $(LIBCOMMON) $(LDLIBS) $(UI_LIBS) \
		$(GTK_LIBS)

# Desktop notifications: only meaningful with NOTIFY=1 (tests/integration/notify.sh).
$(BUILD)/tests/test_notify: tests/gui/test_notify.c tests/harness.h $(BUILD)/ui/notify.o $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(UI_CFLAGS) $(GTK_CFLAGS) $(TEST_CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) \
		-MMD -MP $(ALL_LDFLAGS) -o $@ $< $(BUILD)/ui/notify.o $(LIBCOMMON) $(LDLIBS) $(UI_LIBS) \
		$(GTK_LIBS)

# ---- integration tests (network namespaces; see tests/integration/) ------
# As root they use a new network namespace; otherwise an unprivileged user
# namespace, where the kernel allows it. Never the host's network.

$(BUILD)/itests/%: tests/integration/%.c tests/integration/netns.h tests/harness.h \
                   $(LIBDAEMON) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(TEST_CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP \
		$(ALL_LDFLAGS) -o $@ $< $(LIBDAEMON) $(LIBCOMMON) $(LDLIBS)

test-integration: all $(INTEGRATION_TESTS) $(BUILD)/tests/test_stats_gui
	@fail=0; for t in $(INTEGRATION_TESTS); do \
		$$t || fail=1; \
	done; \
	KISNITCHD=$(CURDIR)/$(BUILD)/kisnitchd tests/integration/run.sh || fail=1; \
	KISNITCHD=$(CURDIR)/$(BUILD)/kisnitchd KISNITCH_GTK=$(CURDIR)/$(BUILD)/kisnitch-gtk \
		tests/integration/ui.sh || fail=1; \
	KISNITCH_GTK=$(CURDIR)/$(BUILD)/kisnitch-gtk tests/integration/stats_win.sh || fail=1; \
	KISNITCHD=$(CURDIR)/$(BUILD)/kisnitchd tests/integration/sysfw.sh || fail=1; \
	STATS_GUI_TEST=$(CURDIR)/$(BUILD)/tests/test_stats_gui tests/integration/stats_gui.sh || fail=1; \
	if $(PKG_CONFIG) --exists openssl; then \
		$(MAKE) --no-print-directory TLS=1 BUILD=$(BUILD)/tls all && \
		KISNITCHD=$(CURDIR)/$(BUILD)/tls/kisnitchd KISNITCH_GTK=$(CURDIR)/$(BUILD)/tls/kisnitch-gtk \
			tests/integration/tls.sh || fail=1; \
	else echo "SKIP (tls): openssl not found"; fi; \
	if $(PKG_CONFIG) --exists libnotify; then \
		$(MAKE) --no-print-directory NOTIFY=1 BUILD=$(BUILD)/notify $(BUILD)/notify/tests/test_notify && \
		NOTIFY_TEST=$(CURDIR)/$(BUILD)/notify/tests/test_notify tests/integration/notify.sh || fail=1; \
	else echo "SKIP (notifications): libnotify not found"; fi; \
	if [ $$fail -ne 0 ]; then echo "*** integration tests FAILED"; exit 1; fi; \
	echo "*** all integration tests passed"

valgrind: $(UNIT_TESTS) $(UI_TESTS)
	@fail=0; for t in $(UNIT_TESTS) $(UI_TESTS); do \
		KS_TEST_VALGRIND=1 valgrind -q --error-exitcode=1 --leak-check=full \
			--errors-for-leak-kinds=definite,indirect $$t >/dev/null || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "*** valgrind FAILED"; exit 1; fi; \
	echo "*** valgrind clean"

# ---- differential test against upstream (needs Go; see tests/diff/run.sh) --

$(BUILD)/diff/ks_diff: tests/diff/ks_diff.c $(LIBDAEMON) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP $(ALL_LDFLAGS) \
		-o $@ $< $(LIBDAEMON) $(LIBCOMMON) $(LDLIBS)

diff:
	tests/diff/run.sh

# The pop-up against upstream's Python code (needs the submodule and
# python3 with protobuf, grpc_tools, slugify, unidecode; skips otherwise).
$(BUILD)/diff/ks_prompt_diff: tests/diff/ks_prompt_diff.c $(LIBUI) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(UI_CFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP $(ALL_LDFLAGS) \
		-o $@ $< $(LIBUI) $(LIBCOMMON) $(LDLIBS) $(UI_LIBS)

$(BUILD)/diff/ks_rules_diff: tests/diff/ks_rules_diff.c $(LIBUI) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(UI_CFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP $(ALL_LDFLAGS) \
		-o $@ $< $(LIBUI) $(LIBCOMMON) $(LDLIBS) $(UI_LIBS)

$(BUILD)/diff/ks_prefs_diff: tests/diff/ks_prefs_diff.c $(LIBUI) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(UI_CFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP $(ALL_LDFLAGS) \
		-o $@ $< $(LIBUI) $(LIBCOMMON) $(LDLIBS) $(UI_LIBS)

ui-checklist:
	python3 tools/gen-ui-checklist.py

diff-ui: $(BUILD)/diff/ks_prompt_diff $(BUILD)/diff/ks_rules_diff $(BUILD)/diff/ks_prefs_diff
	KS_PROMPT_DIFF=$(CURDIR)/$(BUILD)/diff/ks_prompt_diff tests/diff/prompt/run.sh
	KS_RULES_DIFF=$(CURDIR)/$(BUILD)/diff/ks_rules_diff tests/diff/ruleseditor/run.sh
	KS_PREFS_DIFF=$(CURDIR)/$(BUILD)/diff/ks_prefs_diff tests/diff/prefs/run.sh

# ---- static checks --------------------------------------------------------

OWN_SOURCES = common/*.c common/*.h common/grpc/*.c common/grpc/*.h daemon/*.c daemon/*.h daemon/*/*.c \
              daemon/*/*.h ui/*.c ui/*.h tools/*.c tests/harness.h tests/diff/*.c \
              tests/unit/*.c tests/fuzz/*.c tests/integration/*.c \
              tests/integration/*.h

lint:
	@if grep -nE '\b(strcpy|strcat|sprintf|vsprintf|gets)[[:space:]]*\(' $(OWN_SOURCES); then \
		echo "*** banned function used (see docs/PORTING.md section 8)"; exit 1; fi
	@command -v cppcheck >/dev/null || { echo "*** cppcheck not installed"; exit 1; }
	cppcheck --std=c11 --enable=warning,performance,portability \
		--error-exitcode=1 --inline-suppr --quiet \
		--suppress='preprocessorErrorDirective:common/pb/*' \
		-I. -Icommon -Icommon/vendor/cjson \
		-D_POSIX_C_SOURCE=200809L -DKS_VERSION='"lint"' -DKS_UPSTREAM_VERSION='"lint"' -DKS_FIXTURES_DIR='"."' \
		$(PCRE2_CFLAGS) common/*.c common/grpc daemon ui tests/unit tests/integration

# ---- fuzzing (clang + libFuzzer) ------------------------------------------

FUZZ_CC     ?= clang
FUZZ_FLAGS   = -g -O1 -fsanitize=fuzzer,address,undefined
# libFuzzer links libstdc++. On Ubuntu 22.04 clang picks GCC 12, whose
# libstdc++ is often missing: install libstdc++-12-dev or pass e.g.
# FUZZ_LDFLAGS=-L/usr/lib/gcc/x86_64-linux-gnu/11
FUZZ_LDFLAGS ?=
FUZZ_SOURCES = $(COMMON_SRC) $(VENDOR_SRC) $(DAEMON_LIB_SRC)
FUZZ_TIME   ?= 60

$(BUILD)/fuzz/%: tests/fuzz/%.c $(FUZZ_SOURCES)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(CPPFLAGS) $(STDFLAGS) $(FUZZ_FLAGS) -o $@ $< $(FUZZ_SOURCES) \
		$(FUZZ_LDFLAGS) $(LDLIBS)

# The UI's parsers: the UI library (GLib) instead of the daemon's.
FUZZ_UI_SOURCES = $(COMMON_SRC) $(VENDOR_SRC) $(UI_LIB_SRC) $(BUILD)/ui/res.c
$(UI_FUZZERS): $(BUILD)/fuzz/%: tests/fuzz/%.c $(FUZZ_UI_SOURCES)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(CPPFLAGS) $(UI_CFLAGS) $(STDFLAGS) $(FUZZ_FLAGS) -o $@ $< \
		$(FUZZ_UI_SOURCES) $(FUZZ_LDFLAGS) $(LDLIBS) $(UI_LIBS)

fuzz: $(FUZZERS)

# Short smoke run of every fuzzer; raise FUZZ_TIME for real campaigns.
fuzz-run: $(FUZZERS)
	@for f in $(FUZZERS); do \
		n=$$(basename $$f); mkdir -p $(BUILD)/fuzz/corpus/$$n; \
		seeds=tests/fuzz/corpus/$$n; [ -d $$seeds ] || seeds=; \
		$$f -max_total_time=$(FUZZ_TIME) $(BUILD)/fuzz/corpus/$$n $$seeds || exit 1; \
	done

clean:
	rm -rf $(BUILD)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
