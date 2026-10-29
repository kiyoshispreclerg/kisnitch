/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The tasks scheduler: cron-like ticks at configured times, weekdays,
 * hours, minutes and seconds. Port of upstream daemon/tasks/scheduler.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: a scheduler owns its timers; the configuration is copied. The
 * loop is borrowed.
 */
#ifndef KS_DAEMON_TASKS_SCHEDULER_H
#define KS_DAEMON_TASKS_SCHEDULER_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "common/json_schema.h"

struct ks_evloop;

/* scheduler.Config ("time", "weekday", "hour", "minute", "second",
 * "repeat"). Weekdays: 0 is Sunday. */
struct ks_sched_config {
    struct ks_strs time;
    struct ks_ints weekday, hour, minute, second;
    bool repeat;
};
extern const struct ks_schema ks_sched_config_schema;

typedef void (*ks_sched_cb)(void *ctx);

struct ks_sched;
struct ks_sched *ks_sched_new(struct ks_evloop *loop, const struct ks_sched_config *cfg,
                              ks_sched_cb cb, void *ctx);
/* Start(): the daily timers of "time", and the ticker checking the
 * weekday/hour/minute/second lists. */
int ks_sched_start(struct ks_sched *s);
void ks_sched_free(struct ks_sched *s);

/* NewDailyTicker: parses "15:04:05" or "15:04" and returns how long to
 * wait from `now` until that time (today or tomorrow); 1 ms when it's now.
 * -1 if `tm` isn't a time. */
int64_t ks_sched_daily_wait(const char *tm, const struct timespec *now);

/* The ticker's resolution (time.Second, Minute or Hour) for `cfg`. */
int64_t ks_sched_resolution(const struct ks_sched_config *cfg);
/* How many ticks a daily timer firing at `now` sends: one per matching
 * entry of "weekday". */
int ks_sched_daily_ticks(const struct ks_sched_config *cfg, const struct tm *now);
/* Whether the ticker sends a tick at `now`, upstream's combinations
 * included: hours+minutes or hours+seconds without the third never tick. */
bool ks_sched_matches(const struct ks_sched_config *cfg, const struct tm *now);

#endif
