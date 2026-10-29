/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/scheduler/scheduler.go. Upstream's tickers
 * and goroutines are timers on the event loop.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/tasks/scheduler.h"

#include <stdlib.h>
#include <string.h>

#include "common/duration.h"
#include "common/log.h"
#include "daemon/evloop.h"

static const struct ks_schema_field sched_fields[] = {
    KS_FIELD(struct ks_sched_config, "time", KS_T_STRS, time),
    KS_FIELD(struct ks_sched_config, "weekday", KS_T_INTS, weekday),
    KS_FIELD(struct ks_sched_config, "hour", KS_T_INTS, hour),
    KS_FIELD(struct ks_sched_config, "minute", KS_T_INTS, minute),
    KS_FIELD(struct ks_sched_config, "second", KS_T_INTS, second),
    KS_FIELD(struct ks_sched_config, "repeat", KS_T_BOOL, repeat),
};
const struct ks_schema ks_sched_config_schema =
    KS_SCHEMA("scheduler.Config", struct ks_sched_config, sched_fields);

struct daily {
    struct ks_sched *s;
    struct ks_timer *timer;
};

struct ks_sched {
    struct ks_evloop *loop;
    struct ks_sched_config cfg;
    ks_sched_cb cb;
    void *ctx;
    struct daily *daily; /* Tickers */
    size_t ndaily;
    struct ks_timer *ticker; /* Ticker */
};

/* ---- time.Parse("15:04:05") and ("15:04") ------------------------------ */

static bool digit(char c)
{
    return c >= '0' && c <= '9';
}

/* `fixed`: exactly two digits (04, 05); otherwise one or two (15) */
static const char *num2(const char *s, bool fixed, int *out)
{
    if (!digit(s[0]))
        return NULL;
    if (!digit(s[1])) {
        if (fixed)
            return NULL;
        *out = s[0] - '0';
        return s + 1;
    }
    *out = (s[0] - '0') * 10 + (s[1] - '0');
    return s + 2;
}

static bool parse_clock(const char *v, bool with_seconds, int *h, int *m, int *sec)
{
    *sec = 0;
    if ((v = num2(v, false, h)) == NULL || *h > 23 || *v++ != ':')
        return false;
    if ((v = num2(v, true, m)) == NULL || *m > 59)
        return false;
    if (with_seconds) {
        if (*v++ != ':' || (v = num2(v, true, sec)) == NULL || *sec > 59)
            return false;
        /* Go takes a fraction after the seconds even if the layout has none */
        if ((v[0] == '.' || v[0] == ',') && digit(v[1]))
            for (v++; digit(*v); v++)
                ;
    }
    return *v == '\0'; /* "extra text" otherwise */
}

int64_t ks_sched_daily_wait(const char *tm, const struct timespec *now)
{
    int h, m, s;
    if (!parse_clock(tm, true, &h, &m, &s) && !parse_clock(tm, false, &h, &m, &s)) {
        ks_debug("[tasks-scheduler] invalid daily ticker time: parsing time \"%s\"", tm);
        return -1;
    }
    time_t t = now->tv_sec;
    struct tm lt;
    if (localtime_r(&t, &lt) == NULL)
        return -1;
    lt.tm_hour = h;
    lt.tm_min = m;
    lt.tm_sec = s;
    lt.tm_isdst = -1;
    int64_t tmd = (int64_t)mktime(&lt) * KS_SECOND;
    int64_t n = (int64_t)now->tv_sec * KS_SECOND + now->tv_nsec;
    int64_t wait = KS_MILLISECOND;
    if (tmd < n)
        wait = 24 * KS_HOUR - (n - tmd);
    else if (tmd > n)
        wait = tmd - n;
    ks_debug("[tasks-scheduler] NewDailyTicker scheduled, waiting to start: %lld ns",
             (long long)wait);
    return wait;
}

/* ---- matching --------------------------------------------------------- */

static bool has(const struct ks_ints *a, int v)
{
    for (size_t i = 0; i < a->len; i++)
        if (a->v[i] == v)
            return true;
    return false;
}

int64_t ks_sched_resolution(const struct ks_sched_config *cfg)
{
    bool hours = cfg->hour.len > 0, mins = cfg->minute.len > 0, secs = cfg->second.len > 0;
    if (mins && !secs)
        return KS_MINUTE;
    if (hours && !mins && !secs)
        return KS_HOUR;
    return KS_SECOND;
}

int ks_sched_daily_ticks(const struct ks_sched_config *cfg, const struct tm *now)
{
    int n = 0;
    for (size_t i = 0; i < cfg->weekday.len; i++)
        if (cfg->weekday.v[i] == now->tm_wday)
            n++;
    return n;
}

bool ks_sched_matches(const struct ks_sched_config *cfg, const struct tm *now)
{
    if (!has(&cfg->weekday, now->tm_wday))
        return false;
    bool hours = cfg->hour.len > 0, mins = cfg->minute.len > 0, secs = cfg->second.len > 0;
    bool hm = hours && has(&cfg->hour, now->tm_hour);
    bool mm = mins && has(&cfg->minute, now->tm_min);
    bool sm = secs && has(&cfg->second, now->tm_sec);
    return (hours && !mins && !secs && hm) || (!hours && mins && !secs && mm) ||
           (!hours && !mins && secs && sm) || (!hours && mins && secs && mm && sm) ||
           (hours && mins && secs && hm && mm && sm);
}

/* ---- timers ----------------------------------------------------------- */

static void now_tm(struct tm *out)
{
    time_t t = time(NULL);
    if (localtime_r(&t, out) == NULL)
        memset(out, 0, sizeof(*out));
}

static void on_daily(void *data)
{
    struct daily *d = data;
    struct tm now;
    now_tm(&now);
    for (int i = ks_sched_daily_ticks(&d->s->cfg, &now); i > 0; i--)
        d->s->cb(d->s->ctx);
}

static void on_ticker(void *data)
{
    struct ks_sched *s = data;
    struct tm now;
    now_tm(&now);
    if (ks_sched_matches(&s->cfg, &now)) {
        ks_trace("[tasks-scheduler] scheduling new job, hour: %d, min: %d, sec: %d", now.tm_hour,
                 now.tm_min, now.tm_sec);
        s->cb(s->ctx);
    }
}

struct ks_sched *ks_sched_new(struct ks_evloop *loop, const struct ks_sched_config *cfg,
                              ks_sched_cb cb, void *ctx)
{
    struct ks_sched *s = calloc(1, sizeof(*s));
    if (s == NULL)
        return NULL;
    if (ks_schema_copy(&ks_sched_config_schema, &s->cfg, cfg) < 0) {
        free(s);
        return NULL;
    }
    s->loop = loop;
    s->cb = cb;
    s->ctx = ctx;
    return s;
}

int ks_sched_start(struct ks_sched *s)
{
    ks_debug("[tasks-scheduler] Start()");
    if (s->cfg.time.len > 0 && (s->daily = calloc(s->cfg.time.len, sizeof(*s->daily))) == NULL)
        return -1;
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    for (size_t i = 0; i < s->cfg.time.len; i++) {
        int64_t wait = ks_sched_daily_wait(s->cfg.time.v[i], &now);
        if (wait < 0) {
            ks_error("[tasks-scheduler] invalid timer %zu-%s", i, s->cfg.time.v[i]);
            continue;
        }
        struct daily *d = &s->daily[s->ndaily];
        d->s = s;
        /* the remaining time until the configured hour, then every 24h */
        d->timer = ks_evloop_add_timer(s->loop, wait, 24 * KS_HOUR, on_daily, d);
        if (d->timer == NULL)
            return -1;
        s->ndaily++;
        ks_debug("[tasks-scheduler] %zu, %s daily ticker started", i, s->cfg.time.v[i]);
    }
    int64_t res = ks_sched_resolution(&s->cfg);
    s->ticker = ks_evloop_add_timer(s->loop, res, res, on_ticker, s);
    return s->ticker != NULL ? 0 : -1;
}

void ks_sched_free(struct ks_sched *s)
{
    if (s == NULL)
        return;
    for (size_t i = 0; i < s->ndaily; i++)
        ks_evloop_cancel_timer(s->loop, s->daily[i].timer);
    free(s->daily);
    if (s->ticker != NULL)
        ks_evloop_cancel_timer(s->loop, s->ticker);
    ks_schema_free(&ks_sched_config_schema, &s->cfg);
    free(s);
}
