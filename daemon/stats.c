/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/statistics/stats.go and event.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/stats.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/arena.h"
#include "common/log.h"
#include "daemon/config.h"
#include "daemon/loggers.h"
#include "daemon/procmon/process.h"
#include "daemon/protocol.h"
#include "daemon/rules/loader.h"
#include "daemon/rules/rule.h"

static int64_t mono_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void ks_stats_init(struct ks_stats *s, struct ks_loader *rules)
{
    memset(s, 0, sizeof(*s));
    s->started = mono_now();
    s->rules = rules;
    ks_strmap_init(&s->by_proto);
    ks_strmap_init(&s->by_address);
    ks_strmap_init(&s->by_host);
    ks_strmap_init(&s->by_port);
    ks_strmap_init(&s->by_uid);
    ks_strmap_init(&s->by_executable);
    s->max_events = 150;
    s->max_stats = 25;
}

static void event_free(struct ks_stats_event *e)
{
    if (e == NULL)
        return;
    free(e->dst_host);
    ks_proc_unref(e->proc);
    ks_rule_free(e->rule);
    free(e);
}

void ks_stats_empty(struct ks_stats *s)
{
    for (size_t i = 0; i < s->nevents; i++)
        event_free(s->events[i]);
    s->nevents = 0;
    s->new_events = false;
}

void ks_stats_free(struct ks_stats *s)
{
    ks_stats_empty(s);
    free(s->events);
    ks_strmap_clear(&s->by_proto, free);
    ks_strmap_clear(&s->by_address, free);
    ks_strmap_clear(&s->by_host, free);
    ks_strmap_clear(&s->by_port, free);
    ks_strmap_clear(&s->by_uid, free);
    ks_strmap_clear(&s->by_executable, free);
    memset(s, 0, sizeof(*s));
}

void ks_stats_set_limits(struct ks_stats *s, const struct ks_stats_config *cfg)
{
    if (cfg->max_events > 0)
        s->max_events = (size_t)cfg->max_events;
    if (cfg->max_stats > 0)
        s->max_stats = (size_t)cfg->max_stats;
    long long workers = cfg->workers != 0 ? (long long)cfg->workers : 6;
    /* sic: upstream prints the two limits swapped */
    ks_info("Stats, max events: %zu, max stats: %zu, max workers: %lld", s->max_stats,
            s->max_events, workers);
}

void ks_stats_on_dns_response(struct ks_stats *s)
{
    s->dns_responses++;
    s->accepted++;
}

void ks_stats_on_ignored(struct ks_stats *s)
{
    s->ignored++;
    s->accepted++;
}

uint64_t ks_stats_map_get(const struct ks_strmap *m, const char *key)
{
    const uint64_t *v = ks_strmap_get(m, key);
    return v ? *v : 0;
}

struct min_ctx {
    const char *key;
    uint64_t min;
};

static bool find_min(const char *key, void *value, void *ctx)
{
    struct min_ctx *mc = ctx;
    uint64_t v = *(uint64_t *)value;
    if (v < mc->min) {
        mc->min = v;
        mc->key = key;
    }
    return false;
}

/* incMap(): when the map is full, the entry with the fewest hits goes. */
static void inc_map(struct ks_stats *s, struct ks_strmap *m, const char *key)
{
    uint64_t *v = ks_strmap_get(m, key);
    if (v != NULL) {
        (*v)++;
        return;
    }
    if (m->count >= s->max_stats) {
        struct min_ctx mc = {NULL, 9999999999u};
        ks_strmap_filter(m, find_min, &mc);
        if (mc.key != NULL) {
            char *k = strdup(mc.key);
            if (k != NULL)
                free(ks_strmap_del(m, k));
            free(k);
        }
    }
    v = malloc(sizeof(*v));
    if (v == NULL)
        return;
    *v = 1;
    if (ks_strmap_set(m, key, v, NULL) < 0)
        free(v);
}

static uint64_t unix_nano(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

void ks_stats_set_loggers(struct ks_stats *s, struct ks_loggers *l)
{
    s->loggers = l;
}

/* s.logger.Log(con.Serialize(), action, rname) */
static void log_connection(struct ks_stats *s, const struct ks_conn *c, struct ks_proc *proc,
                           const struct ks_rule *match)
{
    if (!ks_loggers_active(s->loggers))
        return;
    struct ks_arena a = {0};
    struct ks_log_event ev = {
        .conn = ks_pb_connection(&a, c, proc),
        .action = match != NULL ? match->action : "<nil>",
        .rule = match != NULL ? match->name : "<nil>",
    };
    if (ev.conn != NULL && !a.failed)
        ks_loggers_log(s->loggers, &ev);
    ks_arena_free(&a);
}

void ks_stats_on_connection(struct ks_stats *s, const struct ks_conn *c,
                            struct ks_proc *proc, const struct ks_rule *match,
                            bool was_missed)
{
    log_connection(s, c, proc, match);
    s->connections++;
    if (was_missed)
        s->rule_misses++;
    else
        s->rule_hits++;
    if (!was_missed && match != NULL && strcmp(match->action, KS_ACTION_ALLOW) == 0)
        s->accepted++;
    else
        s->dropped++;

    char buf[64];
    inc_map(s, &s->by_proto, c->protocol);
    ks_ip_string(&c->dst_ip, buf, sizeof(buf));
    inc_map(s, &s->by_address, buf);
    if (c->dst_host != NULL && c->dst_host[0] != '\0')
        inc_map(s, &s->by_host, c->dst_host);
    snprintf(buf, sizeof(buf), "%u", c->dst_port);
    inc_map(s, &s->by_port, buf);
    snprintf(buf, sizeof(buf), "%lld", c->uid);
    inc_map(s, &s->by_uid, buf);
    inc_map(s, &s->by_executable, proc != NULL && proc->path != NULL ? proc->path : "");

    /* If we reached the limit, shift everything back by one position. */
    while (s->nevents > 0 && s->nevents >= s->max_events) {
        event_free(s->events[0]);
        memmove(&s->events[0], &s->events[1], (s->nevents - 1) * sizeof(*s->events));
        s->nevents--;
    }
    if (was_missed || match == NULL)
        return;

    if (s->nevents == s->cap_events) {
        size_t cap = s->cap_events ? s->cap_events * 2 : 16;
        struct ks_stats_event **ev = realloc(s->events, cap * sizeof(*ev));
        if (ev == NULL)
            return;
        s->events = ev;
        s->cap_events = cap;
    }
    struct ks_stats_event *e = calloc(1, sizeof(*e));
    if (e == NULL)
        return;
    e->unixnano = (int64_t)unix_nano();
    e->conn = *c;
    e->dst_host = strdup(c->dst_host ? c->dst_host : "");
    e->rule = ks_rule_copy(match);
    if (e->dst_host == NULL || e->rule == NULL) {
        event_free(e);
        return;
    }
    e->conn.dst_host = e->dst_host;
    e->proc = proc ? ks_proc_ref(proc) : NULL;
    e->conn.process = proc ? &proc->view : NULL;
    s->events[s->nevents++] = e;
    s->new_events = true;
}

/* Fills one of the By* maps: all the entry types share a layout. */
#define FILL_MAP(a, m, Type, init, out, nout)                                    \
    do {                                                                         \
        struct fill_ctx fc = {(a), NULL, 0, 0};                                  \
        if ((m)->count > 0) {                                                    \
            Type *ents = ks_arena_calloc((a), (m)->count, sizeof(Type));         \
            Type **ptrs = ks_arena_calloc((a), (m)->count, sizeof(Type *));      \
            if (ents == NULL || ptrs == NULL)                                    \
                return NULL;                                                     \
            for (size_t i_ = 0; i_ < (m)->count; i_++) {                         \
                init(&ents[i_]);                                                 \
                ptrs[i_] = &ents[i_];                                            \
            }                                                                    \
            fc.keys = ks_arena_calloc((a), (m)->count, sizeof(char *));          \
            fc.vals = ks_arena_calloc((a), (m)->count, sizeof(uint64_t));        \
            if (fc.keys == NULL || fc.vals == NULL)                              \
                return NULL;                                                     \
            ks_strmap_filter((m), collect, &fc);                                 \
            for (size_t i_ = 0; i_ < fc.n; i_++) {                               \
                ents[i_].key = fc.keys[i_];                                      \
                ents[i_].value = fc.vals[i_];                                    \
            }                                                                    \
            (out) = ptrs;                                                        \
            (nout) = fc.n;                                                       \
        }                                                                        \
    } while (0)

struct fill_ctx {
    struct ks_arena *a;
    char **keys;
    uint64_t *vals;
    size_t n;
};

static bool collect(const char *key, void *value, void *ctx)
{
    struct fill_ctx *fc = ctx;
    fc->keys[fc->n] = (char *)(uintptr_t)key;
    fc->vals[fc->n] = *(uint64_t *)value;
    fc->n++;
    return false;
}

/* Event.Serialize() */
static Protocol__Event *serialize_event(struct ks_arena *a, const struct ks_stats_event *e)
{
    Protocol__Event *pe = ks_arena_alloc(a, sizeof(*pe));
    if (pe == NULL)
        return NULL;
    protocol__event__init(pe);
    time_t secs = (time_t)(e->unixnano / 1000000000);
    struct tm tm;
    char t[32];
    localtime_r(&secs, &tm);
    strftime(t, sizeof(t), "%Y-%m-%d %H:%M:%S", &tm);
    pe->time = ks_arena_strdup(a, t);
    pe->connection = ks_pb_connection(a, &e->conn, e->proc);
    pe->rule = ks_pb_rule(a, e->rule);
    pe->unixnano = e->unixnano;
    if (pe->time == NULL || pe->connection == NULL || pe->rule == NULL)
        return NULL;
    return pe;
}

Protocol__Statistics *ks_stats_serialize(struct ks_stats *s, struct ks_arena *a)
{
    if (!s->new_events)
        return NULL;
    Protocol__Statistics *ps = ks_arena_alloc(a, sizeof(*ps));
    if (ps == NULL)
        return NULL;
    protocol__statistics__init(ps);
    ps->daemon_version = (char *)(uintptr_t)KS_UPSTREAM_VERSION;
    ps->rules = s->rules ? ks_loader_num_rules(s->rules) : 0;
    ps->uptime = (uint64_t)((mono_now() - s->started) / 1000000000);
    ps->dns_responses = s->dns_responses;
    ps->connections = s->connections;
    ps->ignored = s->ignored;
    ps->accepted = s->accepted;
    ps->dropped = s->dropped;
    ps->rule_hits = s->rule_hits;
    ps->rule_misses = s->rule_misses;

    if (s->nevents > 0) {
        ps->events = ks_arena_calloc(a, s->nevents, sizeof(*ps->events));
        if (ps->events == NULL)
            return NULL;
        for (size_t i = 0; i < s->nevents; i++)
            if ((ps->events[i] = serialize_event(a, s->events[i])) == NULL)
                return NULL;
        ps->n_events = s->nevents;
    }
    FILL_MAP(a, &s->by_proto, Protocol__Statistics__ByProtoEntry,
             protocol__statistics__by_proto_entry__init, ps->by_proto, ps->n_by_proto);
    FILL_MAP(a, &s->by_address, Protocol__Statistics__ByAddressEntry,
             protocol__statistics__by_address_entry__init, ps->by_address,
             ps->n_by_address);
    FILL_MAP(a, &s->by_host, Protocol__Statistics__ByHostEntry,
             protocol__statistics__by_host_entry__init, ps->by_host, ps->n_by_host);
    FILL_MAP(a, &s->by_port, Protocol__Statistics__ByPortEntry,
             protocol__statistics__by_port_entry__init, ps->by_port, ps->n_by_port);
    FILL_MAP(a, &s->by_uid, Protocol__Statistics__ByUidEntry,
             protocol__statistics__by_uid_entry__init, ps->by_uid, ps->n_by_uid);
    FILL_MAP(a, &s->by_executable, Protocol__Statistics__ByExecutableEntry,
             protocol__statistics__by_executable_entry__init, ps->by_executable,
             ps->n_by_executable);
    return ps;
}
