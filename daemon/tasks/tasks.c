/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/main.go and base/main.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/tasks/tasks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "cJSON.h"
#include "common/duration.h"
#include "common/log.h"
#include "daemon/evloop.h"

struct ks_taskmgr {
    struct ks_evloop *loop;
    ks_task_sink sink;
    void *ctx;
    struct ks_task **tasks; /* insertion order */
    size_t n, cap;
    /* the task whose iteration is running: removing it defers the free */
    struct ks_task *firing;
    bool firing_removed;
};

struct ks_task *ks_task_new(const char *name, const struct ks_task_ops *ops, void *priv)
{
    struct ks_task *t = calloc(1, sizeof(*t));
    if (t == NULL || (t->name = strdup(name)) == NULL) {
        free(t);
        if (ops->free != NULL)
            ops->free(priv);
        return NULL;
    }
    t->ops = ops;
    t->priv = priv;
    return t;
}

void ks_task_free(struct ks_task *t)
{
    if (t == NULL)
        return;
    if (t->ops->free != NULL)
        t->ops->free(t->priv);
    free(t->name);
    free(t);
}

void ks_task_emit(struct ks_task *t, const char *data, const char *err)
{
    t->mgr->sink(t->mgr->ctx, t, err ? NULL : data, err);
}

struct ks_evloop *ks_task_loop(const struct ks_task *t)
{
    return t->mgr->loop;
}

int ks_task_parse_interval(const char *s, int64_t *ns, char *err, size_t errlen)
{
    if (s == NULL || s[0] == '\0')
        s = "5s";
    if (ks_parse_duration(s, ns, err, errlen) < 0)
        return -1;
    if (*ns <= 0) {
        snprintf(err, errlen, "non-positive interval for NewTicker");
        return -1;
    }
    return 0;
}

struct ks_taskmgr *ks_taskmgr_new(struct ks_evloop *loop, ks_task_sink sink, void *ctx)
{
    struct ks_taskmgr *m = calloc(1, sizeof(*m));
    if (m == NULL)
        return NULL;
    m->loop = loop;
    m->sink = sink;
    m->ctx = ctx;
    return m;
}

static void stop_task(struct ks_taskmgr *m, struct ks_task *t)
{
    if (t->timer != NULL) {
        ks_evloop_cancel_timer(m->loop, t->timer);
        t->timer = NULL;
    }
    t->running = false;
}

static void release(struct ks_taskmgr *m, struct ks_task *t)
{
    stop_task(m, t);
    if (t == m->firing)
        m->firing_removed = true;
    else
        ks_task_free(t);
}

static void on_tick(void *data)
{
    struct ks_task *t = data;
    struct ks_taskmgr *m = t->mgr;
    char err[1024] = "";
    char *out = NULL;

    m->firing = t;
    m->firing_removed = false;
    enum ks_task_status st = t->ops->run(t, &out, err, sizeof(err));
    if (st == KS_TASK_EXIT) {
        /* the goroutine exits; the task stays added */
        ks_debug("[tasks] %s stopped: %s", t->name, err);
        stop_task(m, t);
    }
    if (st == KS_TASK_RESULT && out != NULL)
        m->sink(m->ctx, t, out, NULL);
    else if (st == KS_TASK_ERROR)
        m->sink(m->ctx, t, NULL, err);
    free(out);
    bool removed = m->firing_removed;
    m->firing = NULL;
    m->firing_removed = false;
    if (removed)
        ks_task_free(t);
}

int ks_taskmgr_add(struct ks_taskmgr *m, struct ks_task *t, char *err, size_t errlen)
{
    if (ks_taskmgr_get(m, t->name) != NULL) {
        snprintf(err, errlen, "task with name %s already exists", t->name);
        ks_task_free(t);
        return -1;
    }
    if (m->n == m->cap) {
        size_t cap = m->cap ? m->cap * 2 : 8;
        struct ks_task **v = realloc(m->tasks, cap * sizeof(*v));
        if (v == NULL) {
            snprintf(err, errlen, "out of memory");
            ks_task_free(t);
            return -1;
        }
        m->tasks = v;
        m->cap = cap;
    }
    ks_important("[tasks] Adding task: %s", t->name);
    m->tasks[m->n++] = t;
    t->mgr = m;

    char serr[512] = "";
    if (t->ops->start != NULL && t->ops->start(t, serr, sizeof(serr)) < 0) {
        /* upstream logs it from the goroutine; AddTask already succeeded */
        ks_debug("[tasks] Failed to start task %s: %s", t->name, serr);
        return 0;
    }
    if (t->ops->run == NULL) { /* it runs on its own */
        t->running = true;
        ks_debug("Task Added: %s", t->name);
        return 0;
    }
    int64_t first = t->delay_first && t->interval_ns > 0 ? t->interval_ns : 0;
    t->timer = ks_evloop_add_timer(m->loop, first, t->interval_ns > 0 ? t->interval_ns : 0,
                                   on_tick, t);
    if (t->timer == NULL) {
        ks_debug("[tasks] Failed to start task %s: out of memory", t->name);
        return 0;
    }
    t->running = true;
    ks_debug("Task Added: %s", t->name);
    return 0;
}

static ssize_t find(const struct ks_taskmgr *m, const char *name)
{
    for (size_t i = 0; i < m->n; i++)
        if (strcmp(m->tasks[i]->name, name) == 0)
            return (ssize_t)i;
    return -1;
}

int ks_taskmgr_remove(struct ks_taskmgr *m, const char *name, char *err, size_t errlen)
{
    ks_debug("[tasks] RemoveTask() %s", name);
    ssize_t i = find(m, name);
    if (i < 0) {
        snprintf(err, errlen, "task with name %s does not exist", name);
        return -1;
    }
    struct ks_task *t = m->tasks[i];
    memmove(&m->tasks[i], &m->tasks[i + 1], (m->n - (size_t)i - 1) * sizeof(*m->tasks));
    m->n--;
    ks_debug("Task removed: %s", t->name);
    ks_debug("[tasks] RemoveTask() stopping task %s", t->name);
    release(m, t);
    return 0;
}

struct ks_task *ks_taskmgr_get(struct ks_taskmgr *m, const char *name)
{
    ssize_t i = find(m, name);
    return i < 0 ? NULL : m->tasks[i];
}

size_t ks_taskmgr_count(const struct ks_taskmgr *m)
{
    return m->n;
}

void ks_taskmgr_stop_temp(struct ks_taskmgr *m)
{
    for (size_t i = 0; i < m->n;) {
        struct ks_task *t = m->tasks[i];
        if (!t->temporary) {
            i++;
            continue;
        }
        ks_debug("[tasks] Stopping temporary task %s", t->name);
        char err[256];
        ks_taskmgr_remove(m, t->name, err, sizeof(err));
    }
}

void ks_taskmgr_stop_all(struct ks_taskmgr *m)
{
    while (m->n > 0) {
        ks_debug("[tasks] Stopping task %s", m->tasks[0]->name);
        char err[256];
        ks_taskmgr_remove(m, m->tasks[0]->name, err, sizeof(err));
    }
}

void ks_taskmgr_free(struct ks_taskmgr *m)
{
    if (m == NULL)
        return;
    ks_taskmgr_stop_all(m);
    free(m->tasks);
    free(m);
}

/* ---- helpers for the notification handlers --------------------------- */

static const char *go_type(const cJSON *v)
{
    if (v == NULL || cJSON_IsNull(v))
        return NULL;
    if (cJSON_IsString(v))
        return "string";
    if (cJSON_IsNumber(v))
        return "float64";
    if (cJSON_IsBool(v))
        return "bool";
    if (cJSON_IsArray(v))
        return "[]interface {}";
    return "map[string]interface {}";
}

const char *ks_task_assert(const cJSON *v, const char *want, char *err, size_t errlen)
{
    const char *have = go_type(v);
    if (have != NULL && strcmp(have, want) == 0)
        return NULL;
    if (have == NULL)
        snprintf(err, errlen, "interface conversion: interface {} is nil, not %s", want);
    else
        snprintf(err, errlen, "interface conversion: interface {} is %s, not %s", have, want);
    return err;
}

/* strconv.Quote, for the printable ASCII the UIs send; other bytes as \xNN. */
static void go_quote(const char *s, char *buf, size_t len)
{
    size_t o = 0;
    if (len < 3) {
        if (len > 0)
            buf[0] = '\0';
        return;
    }
    buf[o++] = '"';
    for (; *s != '\0' && o + 5 < len; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            buf[o++] = '\\';
            buf[o++] = (char)c;
        } else if (c == '\n') {
            buf[o++] = '\\';
            buf[o++] = 'n';
        } else if (c == '\t') {
            buf[o++] = '\\';
            buf[o++] = 't';
        } else if (c == '\r') {
            buf[o++] = '\\';
            buf[o++] = 'r';
        } else if (c < 0x20 || c == 0x7f) {
            o += (size_t)snprintf(buf + o, len - o, "\\x%02x", c);
        } else {
            buf[o++] = (char)c;
        }
    }
    buf[o++] = '"';
    buf[o] = '\0';
}

int ks_task_atoi(const char *s, long long *out, char *err, size_t errlen)
{
    const char *p = s;
    bool neg = false;
    if (*p == '+' || *p == '-')
        neg = *p++ == '-';
    bool syntax = *p == '\0';
    unsigned long long v = 0;
    bool range = false;
    for (; !syntax && *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            syntax = true;
            break;
        }
        if (v > (9223372036854775808ULL - (unsigned)(*p - '0')) / 10)
            range = true;
        else
            v = v * 10 + (unsigned)(*p - '0');
    }
    if (!syntax && !range && (neg ? v > 9223372036854775808ULL : v > 9223372036854775807ULL))
        range = true;
    if (syntax || range) {
        char q[256];
        go_quote(s, q, sizeof(q));
        snprintf(err, errlen, "strconv.Atoi: parsing %s: %s", q,
                 syntax ? "invalid syntax" : "value out of range");
        return -1;
    }
    *out = neg ? (long long)(0 - v) : (long long)v;
    return 0;
}
