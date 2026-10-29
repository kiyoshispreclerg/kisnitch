/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/log/formats.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/logformats.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"
#include "common/json_util.h"

/* syslog.LOG_NOTICE|syslog.LOG_DAEMON */
#define SYSLOG_LEVEL "29"

struct sb {
    char *p;
    size_t len, cap;
    bool oom;
};

static void put(struct sb *b, const char *s, size_t n)
{
    if (b->oom)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 256;
        while (cap < b->len + n + 1)
            cap *= 2;
        char *np = realloc(b->p, cap);
        if (np == NULL) {
            b->oom = true;
            return;
        }
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void puts_(struct sb *b, const char *s)
{
    put(b, s != NULL ? s : "", strlen(s != NULL ? s : ""));
}

static void putf(struct sb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void putf(struct sb *b, const char *fmt, ...)
{
    char buf[64];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0)
        put(b, buf, (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1);
}

static char *finish(struct sb *b)
{
    if (b->oom) {
        free(b->p);
        return NULL;
    }
    if (b->p == NULL)
        return strdup("");
    return b->p;
}

/* fmt %v of a value: nil is "<nil>" */
static const char *v(const char *s)
{
    return s != NULL ? s : "<nil>";
}

static int cmp_key(const void *a, const void *b)
{
    const Protocol__Connection__ProcessChecksumsEntry *x =
        *(const Protocol__Connection__ProcessChecksumsEntry *const *)a;
    const Protocol__Connection__ProcessChecksumsEntry *y =
        *(const Protocol__Connection__ProcessChecksumsEntry *const *)b;
    return strcmp(x->key, y->key);
}

/* connToSD. The checksums map is iterated in key order (random upstream). */
static void conn_to_sd(struct sb *b, const Protocol__Connection *c)
{
    puts_(b, " SRC=\"");
    puts_(b, c->src_ip);
    putf(b, "\" SPT=\"%u\" DST=\"", c->src_port);
    puts_(b, c->dst_ip);
    puts_(b, "\" DSTHOST=\"");
    puts_(b, c->dst_host);
    putf(b, "\" DPT=\"%u\" PROTO=\"", c->dst_port);
    puts_(b, c->protocol);
    putf(b, "\" PID=\"%u\" UID=\"%u\" PATH=\"", c->process_id, c->user_id);
    puts_(b, c->process_path);
    puts_(b, "\" CMDLINE=\"");
    for (size_t i = 0; i < c->n_process_args; i++) {
        if (i > 0)
            puts_(b, " ");
        puts_(b, c->process_args[i]);
    }
    puts_(b, "\" CWD=\"");
    puts_(b, c->process_cwd);
    puts_(b, "\" CHECKSUMS=\"");
    Protocol__Connection__ProcessChecksumsEntry **sums = NULL;
    if (c->n_process_checksums > 0 &&
        (sums = malloc(c->n_process_checksums * sizeof(*sums))) != NULL) {
        memcpy(sums, c->process_checksums, c->n_process_checksums * sizeof(*sums));
        qsort(sums, c->n_process_checksums, sizeof(*sums), cmp_key);
        for (size_t i = 0; i < c->n_process_checksums; i++) {
            puts_(b, sums[i]->key);
            puts_(b, ":");
            puts_(b, sums[i]->value);
        }
        free(sums);
    }
    puts_(b, "\" PROCTREE=\"");
    for (size_t i = 0; i < c->n_process_tree; i++) {
        puts_(b, c->process_tree[i]->key);
        puts_(b, ",");
    }
    puts_(b, "\"");
}

/* The values after the first: " ARG<n>=\"<value>\"" */
static void args_sd(struct sb *b, const struct ks_log_event *ev)
{
    putf(b, " ARG1=\"");
    puts_(b, v(ev->action));
    putf(b, "\" ARG2=\"");
    puts_(b, v(ev->rule));
    puts_(b, "\"");
}

static void first_sd(struct sb *b, const struct ks_log_event *ev)
{
    if (ev->conn != NULL) {
        conn_to_sd(b, ev->conn);
    } else {
        puts_(b, " TASK=\"");
        puts_(b, ev->task_name);
        puts_(b, "\" DATA=\"");
        puts_(b, ev->task_data);
        puts_(b, "\"");
    }
}

static void stamp(time_t now, char *buf, size_t len)
{
    /* time.RFC3339: no fraction */
    ks_go_time_rfc3339nano((int64_t)now, 0, buf, len);
}

static char *rfc5424(const struct ks_log_event *ev, const char *hostname, const char *tag,
                     time_t now)
{
    struct sb sd = {0}, b = {0};
    first_sd(&sd, ev);
    args_sd(&sd, ev);
    char ts[KS_GO_TIME_STRLEN];
    stamp(now, ts, sizeof(ts));
    putf(&b, "<" SYSLOG_LEVEL ">1 ");
    puts_(&b, ts);
    puts_(&b, " ");
    puts_(&b, hostname);
    puts_(&b, " ");
    puts_(&b, tag);
    putf(&b, " %ld %s - [", (long)getpid(), ev->conn ? "CONNECTION" : "TASK_NOTIFICATION");
    puts_(&b, sd.p != NULL ? sd.p + 1 : ""); /* out[1:] */
    puts_(&b, "]\n");
    free(sd.p);
    if (sd.oom)
        b.oom = true;
    return finish(&b);
}

static char *rfc3164(const struct ks_log_event *ev, const char *hostname, const char *tag,
                     time_t now)
{
    struct sb sd = {0}, b = {0};
    first_sd(&sd, ev);
    args_sd(&sd, ev);
    char ts[KS_GO_TIME_STRLEN];
    stamp(now, ts, sizeof(ts));
    putf(&b, "<" SYSLOG_LEVEL ">");
    puts_(&b, ts);
    puts_(&b, " ");
    puts_(&b, hostname);
    puts_(&b, " ");
    puts_(&b, tag);
    putf(&b, "[%ld]: [", (long)getpid());
    puts_(&b, sd.p != NULL ? sd.p + 1 : "");
    puts_(&b, "]\n");
    free(sd.p);
    if (sd.oom)
        b.oom = true;
    return finish(&b);
}

/* fmt.Sprint of each value and ",", the last comma removed; no newline */
static char *csv(const struct ks_log_event *ev)
{
    struct sb b = {0};
    const Protocol__Connection *c = ev->conn;
    if (c != NULL) {
        puts_(&b, c->src_ip);
        putf(&b, ",%u,", c->src_port);
        puts_(&b, c->dst_ip);
        puts_(&b, ",");
        puts_(&b, c->dst_host);
        putf(&b, ",%u,", c->dst_port);
        puts_(&b, c->protocol);
        putf(&b, ",%u,%u,", c->process_id, c->user_id);
        puts_(&b, c->process_path);
        puts_(&b, ",[");
        for (size_t i = 0; i < c->n_process_args; i++) {
            if (i > 0)
                puts_(&b, " ");
            puts_(&b, c->process_args[i]);
        }
        puts_(&b, "],");
        puts_(&b, c->process_cwd);
        puts_(&b, ",");
    } else {
        /* %v of TaskNotification{Data, Name} */
        puts_(&b, "{");
        puts_(&b, ev->task_data);
        puts_(&b, " ");
        puts_(&b, ev->task_name);
        puts_(&b, "},");
    }
    puts_(&b, v(ev->action));
    puts_(&b, ",");
    puts_(&b, v(ev->rule));
    return finish(&b);
}

static bool add_str_omit(cJSON *o, const char *k, const char *s)
{
    return s == NULL || s[0] == '\0' || cJSON_AddStringToObject(o, k, s) != NULL;
}

static bool add_uint_omit(cJSON *o, const char *k, uint32_t n)
{
    return n == 0 || ks_json_add_uint(o, k, n) != NULL;
}

static int cmp_env(const void *a, const void *b)
{
    const Protocol__Connection__ProcessEnvEntry *x =
        *(const Protocol__Connection__ProcessEnvEntry *const *)a;
    const Protocol__Connection__ProcessEnvEntry *y =
        *(const Protocol__Connection__ProcessEnvEntry *const *)b;
    return strcmp(x->key, y->key);
}

/* a map<string,string>: sorted keys, omitted when empty */
static bool add_map(cJSON *o, const char *k, void *const *entries, size_t n, bool env)
{
    if (n == 0)
        return true;
    void **sorted = malloc(n * sizeof(*sorted));
    cJSON *m = cJSON_CreateObject();
    bool ok = sorted != NULL && m != NULL;
    if (ok) {
        memcpy(sorted, entries, n * sizeof(*sorted));
        qsort(sorted, n, sizeof(*sorted), env ? cmp_env : cmp_key);
    }
    for (size_t i = 0; ok && i < n; i++) {
        const Protocol__Connection__ProcessEnvEntry *e = sorted[i];
        ok = cJSON_AddStringToObject(m, e->key, e->value) != NULL;
    }
    free(sorted);
    if (ok && cJSON_AddItemToObject(o, k, m))
        return true;
    cJSON_Delete(m);
    return false;
}

/* encoding/json of *protocol.Connection: the generated struct's tags,
 * "<proto name>,omitempty" */
static cJSON *conn_json(const Protocol__Connection *c)
{
    cJSON *o = cJSON_CreateObject();
    bool ok = o != NULL && add_str_omit(o, "protocol", c->protocol) &&
              add_str_omit(o, "src_ip", c->src_ip) && add_uint_omit(o, "src_port", c->src_port) &&
              add_str_omit(o, "dst_ip", c->dst_ip) && add_str_omit(o, "dst_host", c->dst_host) &&
              add_uint_omit(o, "dst_port", c->dst_port) && add_uint_omit(o, "user_id", c->user_id) &&
              add_uint_omit(o, "process_id", c->process_id) &&
              add_str_omit(o, "process_path", c->process_path) &&
              add_str_omit(o, "process_cwd", c->process_cwd);
    if (ok && c->n_process_args > 0) {
        cJSON *a = cJSON_CreateArray();
        ok = a != NULL && cJSON_AddItemToObject(o, "process_args", a);
        for (size_t i = 0; ok && i < c->n_process_args; i++) {
            cJSON *s = cJSON_CreateString(c->process_args[i]);
            ok = s != NULL && cJSON_AddItemToArray(a, s);
            if (!ok)
                cJSON_Delete(s);
        }
        if (!ok && a != NULL && a->string == NULL)
            cJSON_Delete(a);
    }
    ok = ok && add_map(o, "process_env", (void *const *)c->process_env, c->n_process_env, true) &&
         add_map(o, "process_checksums", (void *const *)c->process_checksums,
                 c->n_process_checksums, false);
    if (ok && c->n_process_tree > 0) {
        cJSON *a = cJSON_CreateArray();
        ok = a != NULL && cJSON_AddItemToObject(o, "process_tree", a);
        for (size_t i = 0; ok && i < c->n_process_tree; i++) {
            cJSON *t = cJSON_CreateObject();
            ok = t != NULL && add_str_omit(t, "key", c->process_tree[i]->key) &&
                 add_uint_omit(t, "value", c->process_tree[i]->value) &&
                 cJSON_AddItemToArray(a, t);
            if (!ok)
                cJSON_Delete(t);
        }
    }
    if (!ok) {
        cJSON_Delete(o);
        return NULL;
    }
    return o;
}

/* JSONEventFormat{Event, Rule, Action, Type}, then "\n\n" */
static char *json(const struct ks_log_event *ev)
{
    cJSON *o = cJSON_CreateObject();
    cJSON *e = NULL;
    if (ev->conn != NULL) {
        e = conn_json(ev->conn);
    } else {
        e = cJSON_CreateObject();
        if (e != NULL && (!cJSON_AddStringToObject(e, "Data", ev->task_data ? ev->task_data : "") ||
                          !cJSON_AddStringToObject(e, "Name", ev->task_name ? ev->task_name : ""))) {
            cJSON_Delete(e);
            e = NULL;
        }
    }
    bool ok = o != NULL && e != NULL && cJSON_AddItemToObject(o, "Event", e);
    if (!ok)
        cJSON_Delete(e);
    /* only string values set Action (2nd) and Rule (3rd) */
    ok = ok && cJSON_AddStringToObject(o, "Rule", ev->rule ? ev->rule : "") &&
         cJSON_AddStringToObject(o, "Action", ev->action ? ev->action : "") &&
         ks_json_add_uint(o, "Type", ev->conn ? 0 : 2);
    char *s = ok ? ks_json_print_go(o, false) : NULL;
    cJSON_Delete(o);
    if (s == NULL)
        return NULL;
    size_t n = strlen(s);
    char *out = realloc(s, n + 3);
    if (out == NULL) {
        free(s);
        return NULL;
    }
    memcpy(out + n, "\n\n", 3);
    return out;
}

char *ks_logfmt_transform(enum ks_logfmt f, const struct ks_log_event *ev, const char *hostname,
                          const char *tag, time_t now)
{
    switch (f) {
    case KS_FMT_RFC3164:
        return rfc3164(ev, hostname ? hostname : "", tag ? tag : "", now);
    case KS_FMT_CSV:
        return csv(ev);
    case KS_FMT_JSON:
        return json(ev);
    case KS_FMT_RFC5424:
        break;
    }
    return rfc5424(ev, hostname ? hostname : "", tag ? tag : "", now);
}
