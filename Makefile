include config.mk

BUILD ?= build

COMMON_SRC = common/log.c \
             common/json_util.c \
             common/duration.c
VENDOR_SRC = common/vendor/cjson/cJSON.c
# Everything in the daemon except main.c goes into a static lib so the unit
# tests can link against it.
DAEMON_LIB_SRC = daemon/config.c
DAEMON_MAIN    = daemon/main.c

UNIT_TESTS = $(patsubst tests/unit/%.c,$(BUILD)/tests/%,$(wildcard tests/unit/test_*.c))
FUZZERS    = $(patsubst tests/fuzz/%.c,$(BUILD)/fuzz/%,$(wildcard tests/fuzz/fuzz_*.c))

ALL_CFLAGS  = $(STDFLAGS) $(OPTFLAGS) $(SANFLAGS) $(CFLAGS)
ALL_LDFLAGS = $(SANFLAGS) $(LDFLAGS)

LIBCOMMON = $(BUILD)/libcommon.a
LIBDAEMON = $(BUILD)/libdaemon.a

.PHONY: all test asan valgrind lint fuzz fuzz-run clean

all: $(BUILD)/kisnitchd

$(BUILD)/kisnitchd: $(BUILD)/$(DAEMON_MAIN:.c=.o) $(LIBDAEMON) $(LIBCOMMON)
	$(CC) $(ALL_LDFLAGS) -o $@ $^ $(LDLIBS)

$(LIBCOMMON): $(patsubst %.c,$(BUILD)/%.o,$(COMMON_SRC) $(VENDOR_SRC))
	$(AR) rcs $@ $^

$(LIBDAEMON): $(patsubst %.c,$(BUILD)/%.o,$(DAEMON_LIB_SRC))
	$(AR) rcs $@ $^

$(BUILD)/common/vendor/%.o: common/vendor/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ALL_CFLAGS) $(VENDOR_WARNFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP -c -o $@ $<

# ---- tests ----------------------------------------------------------------

TEST_CPPFLAGS = -DKS_FIXTURES_DIR='"$(CURDIR)/tests/fixtures"'

$(BUILD)/tests/%: tests/unit/%.c tests/harness.h $(LIBDAEMON) $(LIBCOMMON)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(TEST_CPPFLAGS) $(ALL_CFLAGS) $(WARNFLAGS) -MMD -MP \
		$(ALL_LDFLAGS) -o $@ $< $(LIBDAEMON) $(LIBCOMMON) $(LDLIBS)

test: all $(UNIT_TESTS)
	@fail=0; for t in $(UNIT_TESTS); do \
		$$t || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "*** unit tests FAILED"; exit 1; fi; \
	echo "*** all unit tests passed"

asan:
	$(MAKE) BUILD=$(BUILD)/asan SANITIZE=1 test

valgrind: $(UNIT_TESTS)
	@fail=0; for t in $(UNIT_TESTS); do \
		valgrind -q --error-exitcode=1 --leak-check=full \
			--errors-for-leak-kinds=definite,indirect $$t >/dev/null || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "*** valgrind FAILED"; exit 1; fi; \
	echo "*** valgrind clean"

# ---- static checks --------------------------------------------------------

OWN_SOURCES = common/*.c common/*.h daemon/*.c daemon/*.h tests/harness.h \
              tests/unit/*.c tests/fuzz/*.c

lint:
	@if grep -nE '\b(strcpy|strcat|sprintf|vsprintf|gets)[[:space:]]*\(' $(OWN_SOURCES); then \
		echo "*** banned function used (see docs/PORTING.md section 8)"; exit 1; fi
	@command -v cppcheck >/dev/null || { echo "*** cppcheck not installed"; exit 1; }
	cppcheck --std=c11 --enable=warning,performance,portability \
		--error-exitcode=1 --inline-suppr --quiet \
		-I. -Icommon -Icommon/vendor/cjson \
		-D_POSIX_C_SOURCE=200809L -DKS_VERSION='"lint"' -DKS_FIXTURES_DIR='"."' \
		common/*.c daemon tests/unit

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
