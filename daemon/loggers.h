/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The event loggers (Server.Loggers): "remote", "remote_syslog" and
 * "syslog". Port of upstream daemon/log/loggers (logger.go, remote.go,
 * remote_syslog.go, syslog.go).
 *
 * Like upstream, the messages go through a small queue to worker threads,
 * and each remote logger has its own writer threads with a connection to
 * the server. Log() never blocks the loop for more than a millisecond: a
 * full queue drops the message, and too many drops in a row reload the
 * loggers. Stopping never waits for the threads (they may be connecting
 * or resolving a name): they finish on their own.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the manager copies the configurations it loads; the threads hold
 * references to the state they use, which goes away with the last one.
 * ks_loggers_log() copies what it needs from the event.
 */
#ifndef KS_DAEMON_LOGGERS_H
#define KS_DAEMON_LOGGERS_H

#include <stdbool.h>
#include <stddef.h>

#include "common/json_schema.h"
#include "daemon/logformats.h"

#define KS_LOGGER_REMOTE        "remote"
#define KS_LOGGER_REMOTE_SYSLOG "remote_syslog"
#define KS_LOGGER_SYSLOG        "syslog"

struct ks_loggers;

struct ks_loggers *ks_loggers_new(void);
/* Stop(), then frees. Waits up to `wait_ms` for the threads to finish. */
void ks_loggers_free(struct ks_loggers *l, int wait_ms);

/* Load(): `configs` is a ks_array of struct ks_logger_config. */
void ks_loggers_load(struct ks_loggers *l, const struct ks_array *configs);
void ks_loggers_stop(struct ks_loggers *l);
/* Whether any logger is configured (Log() is a no-op otherwise). */
bool ks_loggers_active(const struct ks_loggers *l);

/* Log() */
void ks_loggers_log(struct ks_loggers *l, const struct ks_log_event *ev);

/* Tests: the local syslog socket ("" restores /dev/log and the others). */
void ks_loggers_set_syslog_path(const char *path);
/* Tests: how many messages the remote loggers have written. */
size_t ks_loggers_written(const struct ks_loggers *l);

#endif
