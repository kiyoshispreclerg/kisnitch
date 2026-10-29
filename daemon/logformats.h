/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The formats of the event loggers. Port of upstream daemon/log/formats
 * (rfc5424.go, rfc3164.go, csv.go, json.go, formats.go).
 *
 * Upstream's loggers take a []interface{}: a *protocol.Connection with the
 * action and the rule name (strings, "<nil>" without a rule), or a
 * tasks.TaskNotification with two nil values. struct ks_log_event holds
 * either.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the event borrows everything; the formatted strings are malloc'd
 * and owned by the caller.
 */
#ifndef KS_DAEMON_LOGFORMATS_H
#define KS_DAEMON_LOGFORMATS_H

#include <stdbool.h>
#include <time.h>

#include "common/pb/ui.pb-c.h"

#define KS_LOGFMT_RFC5424 "rfc5424"
#define KS_LOGFMT_RFC3164 "rfc3164"
#define KS_LOGFMT_CSV     "csv"
#define KS_LOGFMT_JSON    "json"

enum ks_logfmt { KS_FMT_RFC5424, KS_FMT_RFC3164, KS_FMT_CSV, KS_FMT_JSON };

struct ks_log_event {
    const Protocol__Connection *conn; /* NULL: a task notification */
    const char *task_name, *task_data;
    const char *action, *rule; /* the 2nd and 3rd values; NULL is nil */
};

/* Transform(). `hostname` and `tag` NULL: called without them (the local
 * syslog logger), so they're empty. `now` is the time stamped. */
char *ks_logfmt_transform(enum ks_logfmt f, const struct ks_log_event *ev, const char *hostname,
                          const char *tag, time_t now);

#endif
