/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/log/log.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/log.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DIM "\033[2m"
#define BOLD "\033[1m"
#define FG_BLACK "\033[30m"
#define FG_WHITE "\033[97m"
#define BG_PURPLE "\033[45m"
#define BG_RED "\033[41m"
#define BG_GREEN "\033[42m"
#define BG_YELLOW "\033[43m"
#define BG_DGRAY "\033[100m"
#define BG_LBLUE "\033[104m"
#define RESET "\033[0m"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int min_level = KS_LOG_INFO;
static bool log_utc = true;
static bool log_micro = false;
static bool with_colors = true;
static FILE *output;     /* NULL means stdout */
static FILE *owned_file; /* opened by ks_log_open_file(), we close it */

struct level_info {
    const char *label;
    const char *color;
};

static struct level_info level_info(int level)
{
    switch (level) {
    case KS_LOG_TRACE:     return (struct level_info){"TRC", FG_WHITE BG_PURPLE};
    case KS_LOG_DEBUG:     return (struct level_info){"DBG", DIM FG_BLACK BG_DGRAY};
    case KS_LOG_INFO:      return (struct level_info){"INF", FG_WHITE BG_GREEN};
    case KS_LOG_IMPORTANT: return (struct level_info){"IMP", FG_WHITE BG_LBLUE};
    case KS_LOG_WARNING:   return (struct level_info){"WAR", FG_WHITE BG_YELLOW};
    case KS_LOG_ERROR:     return (struct level_info){"ERR", FG_WHITE BG_RED};
    case KS_LOG_FATAL:     return (struct level_info){"!!!", FG_WHITE BG_RED BOLD};
    /* Go's map lookup yields empty strings for unknown levels. */
    default:               return (struct level_info){"", ""};
    }
}

void ks_log_set_level(int level)
{
    pthread_mutex_lock(&lock);
    min_level = level;
    pthread_mutex_unlock(&lock);
}

int ks_log_get_level(void)
{
    pthread_mutex_lock(&lock);
    int level = min_level;
    pthread_mutex_unlock(&lock);
    return level;
}

void ks_log_set_utc(bool utc)
{
    pthread_mutex_lock(&lock);
    log_utc = utc;
    pthread_mutex_unlock(&lock);
}

void ks_log_set_micro(bool micro)
{
    pthread_mutex_lock(&lock);
    log_micro = micro;
    pthread_mutex_unlock(&lock);
}

void ks_log_set_colors(bool colors)
{
    pthread_mutex_lock(&lock);
    with_colors = colors;
    pthread_mutex_unlock(&lock);
}

/* Caller holds the lock. */
static void close_owned_locked(void)
{
    if (owned_file != NULL) {
        fclose(owned_file);
        owned_file = NULL;
    }
    output = NULL;
}

void ks_log_set_output(FILE *out)
{
    pthread_mutex_lock(&lock);
    close_owned_locked();
    output = out;
    pthread_mutex_unlock(&lock);
}

void ks_log_close(void)
{
    pthread_mutex_lock(&lock);
    close_owned_locked();
    pthread_mutex_unlock(&lock);
}

int ks_log_open_file(const char *path)
{
    if (strcmp(path, KS_LOG_STDOUT_FILE) == 0) {
        ks_log_set_output(NULL);
        return 0;
    }

    int ret = 0;
    int fd = open(path, O_APPEND | O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
    FILE *f = fd >= 0 ? fdopen(fd, "a") : NULL;
    if (f == NULL) {
        int err = errno;
        if (fd >= 0)
            close(fd);
        ks_log_set_output(NULL);
        ks_error("Error opening log: %s %s", path, strerror(err));
        ret = -1;
    } else {
        pthread_mutex_lock(&lock);
        close_owned_locked();
        owned_file = output = f;
        pthread_mutex_unlock(&lock);
    }
    /* Upstream logs this even when falling back to stdout. */
    ks_important("Start writing logs to %s", path);
    return ret;
}

/* Formats the timestamp like Go's "2006-01-02 15:04:05[.000000]". */
static void format_time(char *buf, size_t len, bool utc, bool micro)
{
    struct timespec ts;
    struct tm tm;

    clock_gettime(CLOCK_REALTIME, &ts);
    if (utc)
        gmtime_r(&ts.tv_sec, &tm);
    else
        localtime_r(&ts.tv_sec, &tm);

    size_t n = strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
    if (micro && n > 0 && n < len)
        snprintf(buf + n, len - n, ".%06ld", ts.tv_nsec / 1000);
}

KS_PRINTF(2, 0)
static void vlog(int level, const char *fmt, va_list ap)
{
    char stackbuf[1024];
    char *heap = NULL; /* used when the message doesn't fit in stackbuf */
    va_list ap2;

    va_copy(ap2, ap);
    int n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
    if (n < 0) {
        va_end(ap2);
        return;
    }
    if ((size_t)n >= sizeof(stackbuf)) {
        heap = malloc((size_t)n + 1);
        if (heap != NULL)
            vsnprintf(heap, (size_t)n + 1, fmt, ap2);
    }
    va_end(ap2);
    /* Truncated is better than nothing if malloc failed. */
    const char *msg = heap != NULL ? heap : stackbuf;

    size_t len = strlen(msg);
    const char *nl = (len > 0 && msg[len - 1] == '\n') ? "" : "\n";

    pthread_mutex_lock(&lock);
    if (level >= min_level) {
        char when[64];
        struct level_info li = level_info(level);
        FILE *out = output != NULL ? output : stdout;

        format_time(when, sizeof(when), log_utc, log_micro);
        if (with_colors)
            fprintf(out, DIM "[%s]" RESET " %s %s " RESET " %s%s",
                    when, li.color, li.label, msg, nl);
        else
            fprintf(out, "[%s]  %s  %s%s", when, li.label, msg, nl);
        fflush(out);
    }
    pthread_mutex_unlock(&lock);

    free(heap);
    /* cppcheck 2.7 reports `heap` as leaked here although it was just freed
     * (a false positive; ASan and valgrind agree). */
    // cppcheck-suppress memleak
}

void ks_log(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog(level, fmt, ap);
    va_end(ap);
}

void ks_fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog(KS_LOG_FATAL, fmt, ap);
    va_end(ap);
    exit(1);
}
