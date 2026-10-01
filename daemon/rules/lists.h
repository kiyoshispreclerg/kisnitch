/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Blocklists for "lists" operators: every "*.*" file (hidden ones excluded) in
 * a directory, merged into one set. Port of upstream
 * daemon/rule/operator_lists.go.
 *
 * Formats, as upstream reads them:
 *   domains  hosts-file lines: "0.0.0.0 host" or "127.0.0.1 host"
 *   regexp   one Go regexp per line
 *   nets     one CIDR per line
 *   simple   one entry per line (lists.ips, lists.hash.md5)
 * Empty lines and lines starting with '#' are skipped (domains: any line not
 * starting with one of the two addresses).
 *
 * Like upstream, the directory is polled every 4 seconds and everything is
 * re-read when a file appears, disappears or changes its modification time.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_lists owns its entries, compiled regexps and its timer.
 */
#ifndef KS_DAEMON_RULES_LISTS_H
#define KS_DAEMON_RULES_LISTS_H

#include <stdbool.h>
#include <stddef.h>

#include "common/netaddr.h"

struct ks_evloop;
struct ks_lists;

enum ks_lists_kind {
    KS_LISTS_DOMAINS, /* lists.domains */
    KS_LISTS_REGEXP,  /* lists.domains_regexp */
    KS_LISTS_NETS,    /* lists.nets */
    KS_LISTS_SIMPLE,  /* lists.ips, lists.hash.md5 */
};

#define KS_LISTS_POLL_INTERVAL_NS (4 * 1000000000LL)

/* Reads the lists in `dir` now and, if `loop` isn't NULL, keeps polling it.
 * NULL on OOM. A missing directory just yields an empty list. */
struct ks_lists *ks_lists_new(enum ks_lists_kind kind, const char *dir,
                              struct ks_evloop *loop);

/* Stops the monitor and frees everything. */
void ks_lists_free(struct ks_lists *l);

/* Domains and simple lists: exact entry lookup. */
bool ks_lists_has(const struct ks_lists *l, const char *s);
/* Regexp lists: true if any expression matches. */
bool ks_lists_match_regexp(struct ks_lists *l, const char *s);
/* Net lists: true if any network contains `ip`. */
bool ks_lists_match_net(const struct ks_lists *l, const struct ks_ip *ip);

/* Number of distinct entries loaded. */
size_t ks_lists_count(const struct ks_lists *l);

/* One monitor iteration: re-reads everything if the files changed. */
void ks_lists_poll(struct ks_lists *l);

#endif
