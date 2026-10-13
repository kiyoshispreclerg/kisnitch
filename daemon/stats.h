/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Connection statistics sent to the UI with each Ping. Port of upstream
 * daemon/statistics/stats.go and event.go.
 *
 * Upstream feeds connections to worker goroutines; here they are counted
 * right away on the event loop (the Workers option is only logged).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_stats owns its maps and events. Each event holds a
 * reference to the connection's process and a copy of the matching rule.
 * The rules loader is borrowed and must outlive the stats.
 */
#ifndef KS_DAEMON_STATS_H
#define KS_DAEMON_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/arena.h"
#include "common/pb/ui.pb-c.h"
#include "common/strmap.h"
#include "daemon/conn.h"

struct ks_loader;
struct ks_proc;
struct ks_rule;
struct ks_stats_config;

struct ks_stats_event {
    int64_t unixnano;     /* Time */
    struct ks_conn conn;  /* dst_host -> owned copy, process -> proc */
    char *dst_host;
    struct ks_proc *proc; /* reference */
    struct ks_rule *rule; /* copy */
};

struct ks_stats {
    int64_t started;           /* Started (CLOCK_MONOTONIC ns) */
    struct ks_loader *rules;
    struct ks_strmap by_executable, by_uid, by_address, by_port, by_host, by_proto;
    struct ks_stats_event **events; /* oldest first */
    size_t nevents, cap_events;

    uint64_t rule_hits, accepted, ignored, connections, rule_misses, dns_responses,
        dropped;
    size_t max_events; /* 150 */
    size_t max_stats;  /* 25 */
    bool new_events;
};

/* statistics.New() */
void ks_stats_init(struct ks_stats *s, struct ks_loader *rules);
void ks_stats_free(struct ks_stats *s);

/* SetLimits() */
void ks_stats_set_limits(struct ks_stats *s, const struct ks_stats_config *cfg);

void ks_stats_on_dns_response(struct ks_stats *s);
void ks_stats_on_ignored(struct ks_stats *s);

/* OnConnectionEvent(): `match` NULL when no rule matched (was_missed). */
void ks_stats_on_connection(struct ks_stats *s, const struct ks_conn *c,
                            struct ks_proc *proc, const struct ks_rule *match,
                            bool was_missed);

/* Serialize(): NULL if there are no new events since the last time.
 * The message borrows from the stats: pack it, then call
 * ks_stats_empty() (upstream empties the events right after building it,
 * whether the ping then works or not). */
Protocol__Statistics *ks_stats_serialize(struct ks_stats *s, struct ks_arena *a);
/* emptyStats() */
void ks_stats_empty(struct ks_stats *s);

/* The value of `key` in one of the By* maps (0 if absent). For tests. */
uint64_t ks_stats_map_get(const struct ks_strmap *m, const char *key);

#endif
