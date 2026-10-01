# Kisnitch build configuration. Override any variable on the command line,
# e.g. `make CC=clang PREFIX=/usr TLS=1`.

VERSION          = 0.0.1
UPSTREAM_VERSION = 1.8.0
FULL_VERSION     = $(VERSION)+os$(UPSTREAM_VERSION)

# Install paths (used from phase 11 on).
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SBINDIR    ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
DESTDIR    ?=

# Optional features (0 = off, 1 = on). Not wired yet: they gain meaning in
# later phases (TLS: 10, EBPF: 9, NOTIFY: 10).
TLS    ?= 0
EBPF   ?= 0
NOTIFY ?= 0

CC         ?= cc
AR         ?= ar
PKG_CONFIG ?= pkg-config

# C11 without GNU extensions; POSIX.1-2008 for strdup, open_memstream, etc.
STDFLAGS  = -std=c11 -D_POSIX_C_SOURCE=200809L
WARNFLAGS = -Wall -Wextra -Werror -Wpedantic -Wshadow -Wformat=2 \
            -Wstrict-prototypes -Wmissing-prototypes -Wvla
# Vendored third-party code is built with the base warnings only.
VENDOR_WARNFLAGS = -Wall -Wextra -Werror

OPTFLAGS ?= -O2 -g
CPPFLAGS += -I. -Icommon/vendor/cjson -DKS_VERSION='"$(FULL_VERSION)"'
LDLIBS   += -pthread

# Required libraries.
PCRE2_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpcre2-8)
PCRE2_LIBS   := $(shell $(PKG_CONFIG) --libs libpcre2-8)
CPPFLAGS += $(PCRE2_CFLAGS)
LDLIBS   += $(PCRE2_LIBS)

# `make asan` sets SANITIZE=1.
SANITIZE ?= 0
ifeq ($(SANITIZE),1)
OPTFLAGS = -O1 -g -fno-omit-frame-pointer
SANFLAGS = -fsanitize=address,undefined -fno-sanitize-recover=all
endif
