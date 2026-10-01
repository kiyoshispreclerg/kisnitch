/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Logging. Port of upstream daemon/log/log.go: same levels, labels, colors
 * and line format ("[date] LBL message"), so log files look identical.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Thread-safe. All state is global and owned by this module.
 */
#ifndef KS_COMMON_LOG_H
#define KS_COMMON_LOG_H

#include <stdbool.h>
#include <stdio.h>

/* Numeric values match upstream (LogLevel in default-config.json). The names
 * avoid LOG_DEBUG & co., which <syslog.h> already defines. */
enum ks_log_level {
    KS_LOG_TRACE = -1,
    KS_LOG_DEBUG = 0,
    KS_LOG_INFO = 1,
    KS_LOG_IMPORTANT = 2,
    KS_LOG_WARNING = 3,
    KS_LOG_ERROR = 4,
    KS_LOG_FATAL = 5,
};

/* Same path upstream treats as "log to stdout" (log.StdoutFile). */
#define KS_LOG_STDOUT_FILE "/dev/stdout"

#if defined(__GNUC__) || defined(__clang__)
#define KS_PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#else
#define KS_PRINTF(fmt, args)
#endif

/* Defaults, as upstream: level INFO, UTC timestamps, no microseconds,
 * colors on, output to stdout. */
void ks_log_set_level(int level);
int ks_log_get_level(void);
void ks_log_set_utc(bool utc);
void ks_log_set_micro(bool micro);
void ks_log_set_colors(bool colors);

/* Sends output to `out` (not owned; caller keeps it open). NULL = stdout.
 * Closes the file previously opened by ks_log_open_file(), if any. */
void ks_log_set_output(FILE *out);

/* Appends logs to `path` (created with mode 0644). KS_LOG_STDOUT_FILE selects
 * stdout. On failure logs an error, falls back to stdout and returns -1. */
int ks_log_open_file(const char *path);

/* Closes the file opened by ks_log_open_file() and returns to stdout. */
void ks_log_close(void);

void ks_log(int level, const char *fmt, ...) KS_PRINTF(2, 3);

#define ks_trace(...)     ks_log(KS_LOG_TRACE, __VA_ARGS__)
#define ks_debug(...)     ks_log(KS_LOG_DEBUG, __VA_ARGS__)
#define ks_info(...)      ks_log(KS_LOG_INFO, __VA_ARGS__)
#define ks_important(...) ks_log(KS_LOG_IMPORTANT, __VA_ARGS__)
#define ks_warning(...)   ks_log(KS_LOG_WARNING, __VA_ARGS__)
#define ks_error(...)     ks_log(KS_LOG_ERROR, __VA_ARGS__)

/* Logs at FATAL level and exits with status 1, like upstream log.Fatal. */
_Noreturn void ks_fatal(const char *fmt, ...) KS_PRINTF(1, 2);

#endif
