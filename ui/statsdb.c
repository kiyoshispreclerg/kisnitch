/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the database parts of upstream ui/opensnitch/nodes.py and
 * ui/opensnitch/service.py (see statsdb.h).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/statsdb.h"

#include <math.h>
#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common/log.h"
#include "common/strmap.h"
#include "ui/nodes.h"

#define NCOUNTERS 5

static const char *const counter_tables[NCOUNTERS] = {"hosts", "procs", "addrs", "ports",
                                                      "users"};

/* _last_stats[addr] and _last_items[table][addr] */
struct ks_stats_node_cache {
    struct ks_stats_node_cache *next;
    char addr[KS_NODE_ADDR_MAX];
    struct ks_strmap events;                 /* unixnano as text */
    struct ks_strmap items[NCOUNTERS];       /* what -> uint64_t * (hits) */
};

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

void ks_statsdb_init(struct ks_statsdb *s, struct ks_db *db, struct ks_rulesdb *rules)
{
    memset(s, 0, sizeof(*s));
    s->db = db;
    s->rules = rules;
}

static void cache_clear(struct ks_stats_node_cache *c)
{
    ks_strmap_clear(&c->events, NULL);
    for (int i = 0; i < NCOUNTERS; i++)
        ks_strmap_clear(&c->items[i], free);
}

void ks_statsdb_free(struct ks_statsdb *s)
{
    while (s->caches != NULL) {
        struct ks_stats_node_cache *c = s->caches;
        s->caches = c->next;
        cache_clear(c);
        free(c);
    }
}

void ks_statsdb_node_forget(struct ks_statsdb *s, const char *addr)
{
    for (struct ks_stats_node_cache **pp = &s->caches; *pp != NULL; pp = &(*pp)->next) {
        if (strcmp((*pp)->addr, addr) == 0) {
            struct ks_stats_node_cache *c = *pp;
            *pp = c->next;
            cache_clear(c);
            free(c);
            return;
        }
    }
}

static struct ks_stats_node_cache *cache_get(struct ks_statsdb *s, const char *addr)
{
    for (struct ks_stats_node_cache *c = s->caches; c != NULL; c = c->next) {
        if (strcmp(c->addr, addr) == 0)
            return c;
    }
    struct ks_stats_node_cache *c = calloc(1, sizeof(*c));
    if (c == NULL)
        return NULL;
    snprintf(c->addr, sizeof(c->addr), "%s", addr);
    ks_strmap_init(&c->events);
    for (int i = 0; i < NCOUNTERS; i++)
        ks_strmap_init(&c->items[i]);
    c->next = s->caches;
    s->caches = c;
    return c;
}

/* ---- dates ------------------------------------------------------------- */

/* datetime.now().strftime(fmt) with "%f" support */
static void now_str(char *buf, size_t len, bool micros)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (localtime_r(&ts.tv_sec, &tm) == NULL) {
        snprintf(buf, len, "%s", "");
        return;
    }
    size_t n = strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
    if (micros && n > 0)
        snprintf(buf + n, len - n, ".%06ld", (long)(ts.tv_nsec / 1000));
}

void ks_statsdb_event_time(int64_t unixnano, char *buf, size_t len)
{
    /* datetime.fromtimestamp(float): modf, then the microseconds rounded
     * half to even (_PyTime_ObjectToTimeval) */
    double d = (double)unixnano / 1000000000.0, ip;
    double fp = modf(d, &ip);
    fp = rint(fp * 1e6);
    if (fp < 0) {
        fp += 1e6;
        ip -= 1.0;
    }
    if (fp >= 1e6) {
        fp -= 1e6;
        ip += 1.0;
    }
    time_t t = (time_t)ip;
    struct tm tm;
    if (localtime_r(&t, &tm) == NULL) {
        snprintf(buf, len, "%s", "");
        return;
    }
    size_t n = strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
    if (n > 0 && (long)fp != 0)
        snprintf(buf + n, len - n, ".%06ld", (long)fp);
}

void ks_statsdb_timedelta(uint64_t secs, char *buf, size_t len)
{
    unsigned long long days = secs / 86400, rem = secs % 86400;
    unsigned h = (unsigned)(rem / 3600), m = (unsigned)(rem % 3600 / 60), sc = (unsigned)(rem % 60);
    if (days > 0)
        snprintf(buf, len, "%llu day%s, %u:%02u:%02u", days, days == 1 ? "" : "s", h, m, sc);
    else
        snprintf(buf, len, "%u:%02u:%02u", h, m, sc);
}

void ks_statsdb_user_id(const char *uid, char *buf, size_t len)
{
    snprintf(buf, len, "%s", uid);
    char *end;
    errno = 0;
    long id = strtol(uid, &end, 10);
    if (uid[0] == '\0' || *end != '\0' || errno != 0 || id < 0)
        return;
    struct passwd pw, *res = NULL;
    char tmp[1024];
    if (getpwuid_r((uid_t)id, &pw, tmp, sizeof(tmp), &res) == 0 && res != NULL)
        snprintf(buf, len, "%s (%s)", pw.pw_name, uid);
}

/* ---- nodes ------------------------------------------------------------- */

void ks_statsdb_reset_status(struct ks_statsdb *s)
{
    const char *a[1] = {KS_NODE_OFFLINE};
    ks_db_run(s->db, "UPDATE OR IGNORE nodes SET status=?", a, 1, NULL);
}

void ks_statsdb_node_insert(struct ks_statsdb *s, const char *addr, const char *name,
                            const char *version, const char *status)
{
    char last_seen[40], now[40];
    now_str(last_seen, sizeof(last_seen), true);
    now_str(now, sizeof(now), false);
    const char *a[10] = {addr, status, name, "", last_seen, "0", "0", "0", version, now};
    ks_db_run(s->db,
              "INSERT OR REPLACE INTO nodes (addr, status, hostname, daemon_version, "
              "daemon_uptime, daemon_rules, cons, cons_dropped, version, last_connection) "
              "VALUES (?,?,?,?,?,?,?,?,?,?)",
              a, 10, NULL);
}

void ks_statsdb_node_update(struct ks_statsdb *s, const char *addr, const char *name,
                            const char *version, const char *status)
{
    char now[40];
    now_str(now, sizeof(now), false);
    const char *a[5] = {name, version, now, status, addr};
    ks_db_run(s->db,
              "UPDATE OR IGNORE nodes SET hostname=?,version=?,last_connection=?,status=? "
              "WHERE addr=?",
              a, 5, NULL);
}

/* ---- statistics -------------------------------------------------------- */

static void u64s(uint64_t v, char *buf, size_t len)
{
    snprintf(buf, len, "%llu", (unsigned long long)v);
}

/* _populate_stats_events() for one table: the pairs not in the last Ping
 * are written (INSERT OR REPLACE), and `cur` becomes the last. */
struct pair {
    const char *what;
    uint64_t hits;
};

static bool populate_counter(struct ks_statsdb *s, struct ks_stats_node_cache *c, int t,
                             const struct pair *items, size_t n)
{
    bool changed = false;
    struct ks_strmap *last = &c->items[t];
    struct ks_strmap fresh;
    ks_strmap_init(&fresh);
    for (size_t i = 0; i < n; i++) {
        char key[512];
        const char *what = items[i].what;
        if (t == 4) /* users: BUG upstream, ids are the same on different machines */
            ks_statsdb_user_id(nz(what), key, sizeof(key));
        else
            snprintf(key, sizeof(key), "%s", nz(what));
        /* the comparison is against the raw key the daemon sent */
        uint64_t *old = ks_strmap_get(last, nz(what));
        if (old == NULL || *old != items[i].hits) {
            changed = true;
            char hits[24], sql[96];
            u64s(items[i].hits, hits, sizeof(hits));
            snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO %s (what,hits) VALUES(?,?)",
                     counter_tables[t]);
            const char *a[2] = {key, hits};
            ks_db_run(s->db, sql, a, 2, NULL);
        }
        uint64_t *h = malloc(sizeof(*h));
        if (h == NULL)
            continue;
        *h = items[i].hits;
        void *prev = NULL;
        if (ks_strmap_set(&fresh, nz(what), h, &prev) < 0)
            free(h);
        free(prev);
    }
    ks_strmap_clear(last, free);
    *last = fresh;
    return changed;
}

#define COUNTER(field, n_field, idx)                                                      \
    do {                                                                                  \
        size_t n_ = st->n_field;                                                          \
        struct pair *p_ = calloc(n_ ? n_ : 1, sizeof(*p_));                               \
        if (p_ != NULL) {                                                                 \
            for (size_t i_ = 0; i_ < n_; i_++) {                                          \
                p_[i_].what = st->field[i_]->key;                                         \
                p_[i_].hits = st->field[i_]->value;                                       \
            }                                                                             \
            if (populate_counter(s, c, idx, p_, n_))                                      \
                r.details = true;                                                         \
            free(p_);                                                                     \
        }                                                                                 \
    } while (0)

struct ks_stats_refresh ks_statsdb_populate(struct ks_statsdb *s, const char *addr,
                                            const char *name, const char *version,
                                            const Protocol__Statistics *st)
{
    struct ks_stats_refresh r = {false, false};
    struct ks_stats_node_cache *c = cache_get(s, addr);
    if (c == NULL)
        return r;

    char uptime[48], rules[24], cons[24], dropped[24], now[40];
    ks_statsdb_timedelta(st->uptime, uptime, sizeof(uptime));
    u64s(st->rules, rules, sizeof(rules));
    u64s(st->connections, cons, sizeof(cons));
    u64s(st->dropped, dropped, sizeof(dropped));
    now_str(now, sizeof(now), false);
    const char *na[10] = {addr, KS_NODE_ONLINE, name, nz(st->daemon_version), uptime,
                          rules, cons, dropped, version, now};
    ks_db_run(s->db,
              "INSERT OR REPLACE INTO nodes (addr, status, hostname, daemon_version, "
              "daemon_uptime, daemon_rules, cons, cons_dropped, version, last_connection) "
              "VALUES (?,?,?,?,?,?,?,?,?,?)",
              na, 10, NULL);

    ks_db_exec(s->db, "BEGIN");
    for (size_t i = 0; i < st->n_events; i++) {
        const Protocol__Event *ev = st->events[i];
        char id[24];
        snprintf(id, sizeof(id), "%lld", (long long)ev->unixnano);
        if (ks_strmap_get(&c->events, id) != NULL)
            continue;
        r.main = true;
        const Protocol__Connection *cn = ev->connection;
        const char *action = ev->rule ? nz(ev->rule->action) : "";
        const char *rname = ev->rule ? nz(ev->rule->name) : "";
        char when[48], sport[16], dport[16], uid[16], pid[16];
        ks_statsdb_event_time(ev->unixnano, when, sizeof(when));
        snprintf(sport, sizeof(sport), "%u", cn ? (unsigned)cn->src_port : 0u);
        snprintf(dport, sizeof(dport), "%u", cn ? (unsigned)cn->dst_port : 0u);
        snprintf(uid, sizeof(uid), "%u", cn ? (unsigned)cn->user_id : 0u);
        snprintf(pid, sizeof(pid), "%u", cn ? (unsigned)cn->process_id : 0u);
        size_t alen = 1;
        for (size_t k = 0; cn && k < cn->n_process_args; k++)
            alen += strlen(nz(cn->process_args[k])) + 1;
        char *args = malloc(alen);
        if (args == NULL)
            continue;
        args[0] = '\0';
        for (size_t k = 0; cn && k < cn->n_process_args; k++) {
            if (k > 0)
                strncat(args, " ", alen - strlen(args) - 1);
            strncat(args, nz(cn->process_args[k]), alen - strlen(args) - 1);
        }
        const char *ca[15] = {when, addr, action, cn ? nz(cn->protocol) : "",
                              cn ? nz(cn->src_ip) : "", sport, cn ? nz(cn->dst_ip) : "",
                              cn ? nz(cn->dst_host) : "", dport, uid, pid,
                              cn ? nz(cn->process_path) : "", args,
                              cn ? nz(cn->process_cwd) : "", rname};
        ks_db_run(s->db,
                  "INSERT OR IGNORE INTO connections (time, node, action, protocol, src_ip, "
                  "src_port, dst_ip, dst_host, dst_port, uid, pid, process, process_args, "
                  "process_cwd, rule) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  ca, 15, NULL);
        free(args);
        ks_rulesdb_update_time(s->rules, when, rname, addr);
    }
    ks_db_exec(s->db, "COMMIT");

    COUNTER(by_host, n_by_host, 0);
    COUNTER(by_executable, n_by_executable, 1);
    COUNTER(by_address, n_by_address, 2);
    COUNTER(by_port, n_by_port, 3);
    COUNTER(by_uid, n_by_uid, 4);

    /* self._last_stats[addr] = this Ping's events */
    ks_strmap_clear(&c->events, NULL);
    for (size_t i = 0; i < st->n_events; i++) {
        char id[24];
        snprintf(id, sizeof(id), "%lld", (long long)st->events[i]->unixnano);
        ks_strmap_set(&c->events, id, c, NULL); /* any non-NULL value */
    }
    return r;
}

void ks_statsdb_alert(struct ks_statsdb *s, const char *node, const char *type,
                      const char *what, const char *body)
{
    char now[40];
    now_str(now, sizeof(now), true);
    const char *a[8] = {now, node, type, "", "", what, body, "0"};
    ks_db_run(s->db,
              "INSERT OR REPLACE INTO alerts (time, node, type, action, priority, what, body, "
              "status) VALUES (?,?,?,?,?,?,?,?)",
              a, 8, NULL);
}
