/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/log/loggers.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _GNU_SOURCE /* pthread_condattr_setclock, MSG_NOSIGNAL */
#include "daemon/loggers.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common/duration.h"
#include "common/log.h"
#include "daemon/config.h"

#define LOG_TAG "opensnitch"
/* restart the connection after these many write errors */
#define MAX_ALLOWED_ERRORS 10
#define WRITE_TIMEOUT KS_SECOND
#define CONN_TIMEOUT (5 * KS_SECOND)
#define REOPEN_INTERVAL (5 * KS_SECOND)
#define QUEUE_FULL_HITS 30

enum lg_kind { LG_REMOTE, LG_REMOTE_SYSLOG, LG_SYSLOG };

struct gen;

struct lg {
    struct gen *g;
    enum lg_kind kind;
    enum ks_logfmt fmt;
    const char *name;
    char *server, *proto, *tag;
    char hostname[256];
    int64_t timeout, conn_timeout;
    uint16_t max_attempts;
    int workers;

    /* remote: writerChan, as a queue of `workers` lines */
    pthread_mutex_t mu;
    pthread_cond_t cond;
    char **q;
    size_t qlen, qhead;
    atomic_int connected; /* writers with a connection */
    atomic_bool closed;   /* Close() */

    /* syslog: the local socket */
    int fd;
};

/* One Load(): the queue, the workers and the loggers. */
struct gen {
    atomic_int refs;
    pthread_mutex_t mu;
    pthread_cond_t cond;
    atomic_bool cancel;
    char ***q; /* each message: one line per logger */
    size_t qlen, qhead, cap;
    struct lg **lgs;
    size_t n;
};

struct ks_loggers {
    struct gen *g;
    struct ks_array configs; /* l.configs */
    int count, workers, queue_full_hits;
};

static char syslog_path[108];
static atomic_size_t written_total;

void ks_loggers_set_syslog_path(const char *path)
{
    snprintf(syslog_path, sizeof(syslog_path), "%s", path != NULL ? path : "");
}

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * KS_SECOND + ts.tv_nsec;
}

static void deadline(struct timespec *ts, int64_t ns)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
    int64_t t = (int64_t)ts->tv_nsec + ns % KS_SECOND;
    ts->tv_sec += (time_t)(ns / KS_SECOND + t / KS_SECOND);
    ts->tv_nsec = (long)(t % KS_SECOND);
}

static void cond_init(pthread_cond_t *c)
{
    pthread_condattr_t a;
    pthread_condattr_init(&a);
    pthread_condattr_setclock(&a, CLOCK_MONOTONIC);
    pthread_cond_init(c, &a);
    pthread_condattr_destroy(&a);
}

/* ---- the state's lifetime --------------------------------------------- */

static void lg_free(struct lg *x)
{
    if (x == NULL)
        return;
    for (size_t i = 0; x->q != NULL && i < x->qlen; i++)
        free(x->q[(x->qhead + i) % (size_t)x->workers]);
    free(x->q);
    if (x->fd >= 0)
        close(x->fd);
    pthread_mutex_destroy(&x->mu);
    pthread_cond_destroy(&x->cond);
    free(x->server);
    free(x->proto);
    free(x->tag);
    free(x);
}

static void gen_unref(struct gen *g)
{
    if (atomic_fetch_sub(&g->refs, 1) != 1)
        return;
    for (size_t i = 0; i < g->qlen; i++) {
        char **m = g->q[(g->qhead + i) % g->cap];
        for (size_t k = 0; k < g->n; k++)
            free(m[k]);
        free(m);
    }
    free(g->q);
    for (size_t i = 0; i < g->n; i++)
        lg_free(g->lgs[i]);
    free(g->lgs);
    pthread_mutex_destroy(&g->mu);
    pthread_cond_destroy(&g->cond);
    free(g);
}

static bool cancelled(const struct lg *x)
{
    return atomic_load(&x->g->cancel) || atomic_load(&x->closed);
}

/* Close(): the remote's writers stop */
static void lg_close(struct lg *x)
{
    pthread_mutex_lock(&x->mu);
    atomic_store(&x->closed, true);
    pthread_cond_broadcast(&x->cond);
    pthread_mutex_unlock(&x->mu);
}

/* ---- remote ----------------------------------------------------------- */

/* net.DialTimeout(proto, addr, timeout) */
static int dial(struct lg *x, char *err, size_t errlen)
{
    bool tcp = strcmp(x->proto, "tcp") == 0;
    if (!tcp && strcmp(x->proto, "udp") != 0) {
        snprintf(err, errlen, "[%s] Network protocol %s not supported (use 'tcp' or 'udp')",
                 x->name, x->proto);
        return -1;
    }
    char host[256], port[32];
    const char *colon = strrchr(x->server, ':');
    if (colon == NULL) {
        snprintf(err, errlen, "dial %s %s: missing port in address", x->proto, x->server);
        return -1;
    }
    const char *h = x->server;
    size_t hl = (size_t)(colon - x->server);
    if (hl >= 2 && h[0] == '[' && h[hl - 1] == ']') {
        h++;
        hl -= 2;
    }
    snprintf(host, sizeof(host), "%.*s", (int)hl, h);
    snprintf(port, sizeof(port), "%s", colon + 1);
    struct addrinfo hints = {.ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM};
    struct addrinfo *res = NULL;
    int r = getaddrinfo(host[0] ? host : NULL, port, &hints, &res);
    if (r != 0) {
        snprintf(err, errlen, "dial %s %s: %s", x->proto, x->server, gai_strerror(r));
        return -1;
    }
    int fd = -1;
    int64_t until = now_ns() + x->conn_timeout;
    for (struct addrinfo *a = res; a != NULL && fd < 0 && !cancelled(x); a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, a->ai_protocol);
        if (fd < 0)
            continue;
        int cr = connect(fd, a->ai_addr, a->ai_addrlen);
        if (cr < 0 && errno != EINPROGRESS) {
            snprintf(err, errlen, "dial %s %s: %s", x->proto, x->server, strerror(errno));
            close(fd);
            fd = -1;
        } else if (cr < 0) {
            /* in slices, to notice a Stop() */
            int soerr = ETIMEDOUT;
            while (!cancelled(x) && now_ns() < until) {
                struct pollfd p = {fd, POLLOUT, 0};
                if (poll(&p, 1, 100) > 0) {
                    socklen_t sl = sizeof(soerr);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
                    break;
                }
            }
            if (soerr != 0) {
                snprintf(err, errlen, "dial %s %s: %s", x->proto, x->server, strerror(soerr));
                close(fd);
                fd = -1;
            }
        }
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int fl = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        struct timeval tv = {(time_t)(x->timeout / KS_SECOND),
                             (suseconds_t)((x->timeout % KS_SECOND) / 1000)};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    } else if (err[0] == '\0') {
        snprintf(err, errlen, "dial %s %s: i/o timeout", x->proto, x->server);
    }
    return fd;
}

/* Open(): retries every 5s, MaxConnectAttempts times (0: forever) */
static int remote_open(struct lg *x)
{
    uint16_t retries = 0;
    for (;;) {
        if (cancelled(x)) {
            ks_info("[%s] %s worker stopped", x->name, x->server);
            return -1;
        }
        ks_debug("[%s] %s trying to connect", x->name, x->server);
        char err[512] = "";
        int fd = dial(x, err, sizeof(err));
        if (fd >= 0) {
            ks_info("[%s] connected to %s", x->name, x->server);
            return fd;
        }
        ks_debug("remote.Dial() %s error: %s", x->server, err);
        ks_debug("[%s] Error opening connection (%s), retrying... (%u/%u)", x->name, x->server,
                 (unsigned)retries, (unsigned)x->max_attempts);
        retries++;
        if (x->max_attempts > 0 && retries > x->max_attempts) {
            ks_info("[%s] %s, Max connections attempts reached, giving up", x->name, x->server);
            return -1;
        }
        struct timespec ts;
        deadline(&ts, REOPEN_INTERVAL);
        pthread_mutex_lock(&x->mu);
        while (!cancelled(x) && pthread_cond_timedwait(&x->cond, &x->mu, &ts) != ETIMEDOUT)
            ;
        pthread_mutex_unlock(&x->mu);
    }
}

static int send_all(int fd, const char *s, size_t n)
{
    while (n > 0) {
        ssize_t w = send(fd, s, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        s += w;
        n -= (size_t)w;
    }
    return 0;
}

/* writerWorker */
static void *remote_writer(void *data)
{
    struct lg *x = data;
    struct gen *g = x->g;
    int errors = 0;
    int fd = remote_open(x);
    if (fd >= 0)
        atomic_fetch_add(&x->connected, 1);
    while (fd >= 0) {
        pthread_mutex_lock(&x->mu);
        while (x->qlen == 0 && !cancelled(x))
            pthread_cond_wait(&x->cond, &x->mu);
        if (cancelled(x)) {
            pthread_mutex_unlock(&x->mu);
            break;
        }
        char *msg = x->q[x->qhead];
        x->qhead = (x->qhead + 1) % (size_t)x->workers;
        x->qlen--;
        pthread_cond_broadcast(&x->cond);
        pthread_mutex_unlock(&x->mu);

        if (send_all(fd, msg, strlen(msg)) < 0) {
            ks_debug("[%s] error writing via writer: %s", x->name, strerror(errno));
            /* the count isn't reset: after the first reopen, every error
             * reopens, as upstream */
            if (++errors > MAX_ALLOWED_ERRORS) {
                ks_warning("[%s] writer: too much errors, review the configuration and / or "
                           "connectivity with the remote server",
                           x->name);
                atomic_fetch_sub(&x->connected, 1);
                close(fd);
                fd = remote_open(x);
                if (fd >= 0)
                    atomic_fetch_add(&x->connected, 1);
            }
        } else {
            atomic_fetch_add(&written_total, 1);
        }
        free(msg);
    }
    ks_info("[%s logger] connection closed (errors: %d)", x->name, errors);
    if (fd >= 0) {
        atomic_fetch_sub(&x->connected, 1);
        close(fd);
    }
    lg_close(x); /* sys.Close() */
    gen_unref(g);
    return NULL;
}

static void remote_write(struct lg *x, char *line)
{
    if (atomic_load(&x->connected) == 0 || cancelled(x)) {
        ks_trace("[%s] %s not connected", x->name, x->server);
        free(line);
        return;
    }
    pthread_mutex_lock(&x->mu);
    while (x->qlen == (size_t)x->workers && !cancelled(x))
        pthread_cond_wait(&x->cond, &x->mu);
    if (cancelled(x)) {
        pthread_mutex_unlock(&x->mu);
        free(line);
        return;
    }
    x->q[(x->qhead + x->qlen) % (size_t)x->workers] = line;
    x->qlen++;
    pthread_cond_broadcast(&x->cond);
    pthread_mutex_unlock(&x->mu);
}

/* ---- syslog (log/syslog to the local daemon) -------------------------- */

static int syslog_connect(void)
{
    static const char *const paths[] = {"/dev/log", "/var/run/syslog", "/var/run/log"};
    static const int types[] = {SOCK_DGRAM, SOCK_STREAM}; /* unixgram, unix */
    for (int t = 0; t < 2; t++) {
        for (size_t i = 0; i < 3; i++) {
            const char *p = syslog_path[0] ? syslog_path : paths[i];
            int fd = socket(AF_UNIX, types[t] | SOCK_CLOEXEC, 0);
            if (fd < 0)
                continue;
            struct sockaddr_un sa = {.sun_family = AF_UNIX};
            snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", p);
            if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0)
                return fd;
            close(fd);
            if (syslog_path[0])
                break;
        }
    }
    return -1;
}

/* Writer.Notice(msg): the local format, "<29>Jan _2 15:04:05 opensnitch[pid]: msg" */
static void syslog_write(struct lg *x, char *msg)
{
    time_t now = time(NULL);
    struct tm lt;
    char ts[32] = "";
    if (localtime_r(&now, &lt) != NULL)
        strftime(ts, sizeof(ts), "%b %e %H:%M:%S", &lt);
    size_t n = strlen(msg);
    const char *nl = n > 0 && msg[n - 1] == '\n' ? "" : "\n";
    size_t len = n + 128;
    char *line = malloc(len);
    if (line != NULL) {
        int w = snprintf(line, len, "<29>%s %s[%ld]: %s%s", ts, LOG_TAG, (long)getpid(), msg, nl);
        pthread_mutex_lock(&x->mu);
        /* writeAndRetry: reconnect once on error */
        bool ok = x->fd >= 0 && send_all(x->fd, line, (size_t)w) == 0;
        if (!ok) {
            if (x->fd >= 0)
                close(x->fd);
            x->fd = syslog_connect();
            ok = x->fd >= 0 && send_all(x->fd, line, (size_t)w) == 0;
        }
        pthread_mutex_unlock(&x->mu);
        if (!ok)
            ks_error("[%s] write error: %s", x->name, strerror(errno));
        else
            atomic_fetch_add(&written_total, 1);
        free(line);
    }
    free(msg);
}

/* ---- the manager ------------------------------------------------------ */

static void *manager_worker(void *data)
{
    struct gen *g = data;
    for (;;) {
        pthread_mutex_lock(&g->mu);
        while (g->qlen == 0 && !atomic_load(&g->cancel))
            pthread_cond_wait(&g->cond, &g->mu);
        if (atomic_load(&g->cancel)) {
            pthread_mutex_unlock(&g->mu);
            break;
        }
        char **m = g->q[g->qhead];
        g->qhead = (g->qhead + 1) % g->cap;
        g->qlen--;
        pthread_mutex_unlock(&g->mu);
        for (size_t i = 0; i < g->n; i++) {
            if (g->lgs[i]->kind == LG_SYSLOG)
                syslog_write(g->lgs[i], m[i]);
            else
                remote_write(g->lgs[i], m[i]);
        }
        free(m);
    }
    ks_debug("logger worker exited");
    gen_unref(g);
    return NULL;
}

static bool spawn(void *(*fn)(void *), void *arg, struct gen *g)
{
    pthread_t t;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    atomic_fetch_add(&g->refs, 1);
    int r = pthread_create(&t, &a, fn, arg);
    pthread_attr_destroy(&a);
    if (r != 0) {
        atomic_fetch_sub(&g->refs, 1);
        ks_error("[loggers] could not start a thread: %s", strerror(r));
        return false;
    }
    return true;
}

static struct lg *lg_new(struct gen *g, const struct ks_logger_config *cfg, enum lg_kind kind)
{
    struct lg *x = calloc(1, sizeof(*x));
    if (x == NULL)
        return NULL;
    x->g = g;
    x->kind = kind;
    x->fd = -1;
    pthread_mutex_init(&x->mu, NULL);
    cond_init(&x->cond);
    atomic_init(&x->connected, 0);
    atomic_init(&x->closed, false);
    x->name = kind == LG_REMOTE        ? KS_LOGGER_REMOTE
              : kind == LG_REMOTE_SYSLOG ? KS_LOGGER_REMOTE_SYSLOG
                                         : KS_LOGGER_SYSLOG;
    x->server = strdup(cfg->server ? cfg->server : "");
    x->proto = strdup(cfg->protocol ? cfg->protocol : "");
    x->tag = strdup(cfg->tag && cfg->tag[0] ? cfg->tag : LOG_TAG);
    if (x->server == NULL || x->proto == NULL || x->tag == NULL) {
        lg_free(x);
        return NULL;
    }
    const char *f = cfg->format ? cfg->format : "";
    x->fmt = KS_FMT_RFC5424;
    if (kind == LG_SYSLOG) {
        if (strcmp(f, KS_LOGFMT_CSV) == 0)
            x->fmt = KS_FMT_CSV;
        return x;
    }
    if (strcmp(f, KS_LOGFMT_RFC3164) == 0)
        x->fmt = KS_FMT_RFC3164;
    else if (strcmp(f, KS_LOGFMT_JSON) == 0)
        x->fmt = KS_FMT_JSON;
    else if (strcmp(f, KS_LOGFMT_CSV) == 0)
        x->fmt = KS_FMT_CSV;
    if (gethostname(x->hostname, sizeof(x->hostname) - 1) < 0)
        snprintf(x->hostname, sizeof(x->hostname), "localhost");
    char err[256];
    if (cfg->write_timeout == NULL || cfg->write_timeout[0] == '\0' ||
        ks_parse_duration(cfg->write_timeout, &x->timeout, err, sizeof(err)) < 0)
        x->timeout = WRITE_TIMEOUT;
    if (cfg->connect_timeout == NULL || cfg->connect_timeout[0] == '\0' ||
        ks_parse_duration(cfg->connect_timeout, &x->conn_timeout, err, sizeof(err)) < 0)
        x->conn_timeout = CONN_TIMEOUT;
    x->max_attempts = cfg->max_connect_attempts;
    x->workers = cfg->workers > 0 ? (int)cfg->workers : 1;
    if ((x->q = calloc((size_t)x->workers, sizeof(*x->q))) == NULL) {
        lg_free(x);
        return NULL;
    }
    return x;
}

static bool known(const char *name)
{
    return strcmp(name, KS_LOGGER_REMOTE) == 0 || strcmp(name, KS_LOGGER_REMOTE_SYSLOG) == 0 ||
           strcmp(name, KS_LOGGER_SYSLOG) == 0;
}

/* the map key: fmt.Sprint(Name, Server, Protocol), or the name for syslog */
static void lg_key(const struct lg *x, char *buf, size_t len)
{
    if (x->kind == LG_SYSLOG)
        snprintf(buf, len, "%s", x->name);
    else
        snprintf(buf, len, "%s%s%s", x->name, x->server, x->proto);
}

static void load(struct ks_loggers *l)
{
    l->count = 0;
    l->workers = 0;
    for (size_t i = 0; i < l->configs.len; i++) {
        const struct ks_logger_config *c = KS_ARRAY_ITEM(l->configs, struct ks_logger_config, i);
        if (c->name != NULL && known(c->name)) {
            l->workers += (int)c->workers;
            l->count++;
        }
    }
    if (l->count == 0)
        return;
    if (l->workers <= 0)
        l->workers = 4;

    struct gen *g = calloc(1, sizeof(*g));
    if (g == NULL)
        return;
    atomic_init(&g->refs, 1);
    atomic_init(&g->cancel, false);
    pthread_mutex_init(&g->mu, NULL);
    cond_init(&g->cond);
    g->cap = (size_t)l->workers;
    g->q = calloc(g->cap, sizeof(*g->q));
    g->lgs = calloc(l->count, sizeof(*g->lgs));
    if (g->q == NULL || g->lgs == NULL) {
        gen_unref(g);
        l->count = 0;
        return;
    }
    l->g = g;
    for (int i = 0; i < l->workers; i++)
        spawn(manager_worker, g, g);

    for (size_t i = 0; i < l->configs.len; i++) {
        const struct ks_logger_config *c = KS_ARRAY_ITEM(l->configs, struct ks_logger_config, i);
        if (c->name == NULL || !known(c->name))
            continue;
        enum lg_kind kind = strcmp(c->name, KS_LOGGER_SYSLOG) == 0 ? LG_SYSLOG
                            : strcmp(c->name, KS_LOGGER_REMOTE) == 0 ? LG_REMOTE
                                                                     : LG_REMOTE_SYSLOG;
        ks_info("New%s logger: %s %s %s", kind == LG_SYSLOG ? "Syslog"
                                          : kind == LG_REMOTE ? "Remote"
                                                              : "RemoteSyslog",
                c->name, c->server ? c->server : "", c->protocol ? c->protocol : "");
        struct lg *x = lg_new(g, c, kind);
        if (x == NULL)
            continue;
        if (kind == LG_SYSLOG) {
            if ((x->fd = syslog_connect()) < 0) {
                /* upstream stores the nil logger and crashes on it */
                ks_error("Error loading logger: Unix syslog delivery error");
                lg_free(x);
                continue;
            }
            ks_info("[%s logger] initialized", x->name);
        }
        /* a duplicate key replaces the previous logger in the map (upstream
         * keeps its workers running); it's closed here, and stays in the
         * list for its writers, receiving nothing */
        char k1[1024], k2[1024];
        lg_key(x, k1, sizeof(k1));
        for (size_t j = 0; j < g->n; j++) {
            lg_key(g->lgs[j], k2, sizeof(k2));
            if (strcmp(k1, k2) == 0)
                lg_close(g->lgs[j]);
        }
        g->lgs[g->n++] = x;
        if (kind != LG_SYSLOG)
            for (int w = 0; w < x->workers; w++)
                spawn(remote_writer, x, g);
    }
}

struct ks_loggers *ks_loggers_new(void)
{
    return calloc(1, sizeof(struct ks_loggers));
}

void ks_loggers_stop(struct ks_loggers *l)
{
    l->count = 0;
    l->workers = 0;
    l->queue_full_hits = 0;
    struct gen *g = l->g;
    l->g = NULL;
    if (g == NULL)
        return;
    pthread_mutex_lock(&g->mu);
    atomic_store(&g->cancel, true);
    pthread_cond_broadcast(&g->cond);
    pthread_mutex_unlock(&g->mu);
    for (size_t i = 0; i < g->n; i++)
        lg_close(g->lgs[i]);
    gen_unref(g);
}

void ks_loggers_load(struct ks_loggers *l, const struct ks_array *configs)
{
    struct ks_array copy = {0};
    if (configs != NULL) {
        /* through a struct holding the array, to reuse ks_schema_copy */
        static const struct ks_schema_field f[] = {
            {"Loggers", KS_T_ARRAY, 0, &ks_logger_config_schema},
        };
        static const struct ks_schema s = {"loggers", sizeof(struct ks_array), f, 1};
        if (ks_schema_copy(&s, &copy, configs) < 0)
            memset(&copy, 0, sizeof(copy));
    }
    ks_schema_free_array(&ks_logger_config_schema, &l->configs);
    l->configs = copy;
    load(l);
}

bool ks_loggers_active(const struct ks_loggers *l)
{
    return l != NULL && l->count > 0 && l->g != NULL;
}

void ks_loggers_log(struct ks_loggers *l, const struct ks_log_event *ev)
{
    if (!ks_loggers_active(l))
        return;
    struct gen *g = l->g;
    pthread_mutex_lock(&g->mu);
    if (g->qlen == g->cap) {
        struct timespec ts;
        deadline(&ts, KS_MILLISECOND);
        while (g->qlen == g->cap && pthread_cond_timedwait(&g->cond, &g->mu, &ts) != ETIMEDOUT)
            ;
    }
    if (g->qlen == g->cap) {
        l->queue_full_hits++;
        ks_debug("loggerMgr.Log() TIMEOUT dispatching log, queued: %zu, queue full hits: %d",
                 g->qlen, l->queue_full_hits);
        bool reload = l->queue_full_hits > QUEUE_FULL_HITS;
        pthread_mutex_unlock(&g->mu);
        if (reload) {
            ks_loggers_stop(l);
            load(l);
        }
        return;
    }
    /* Transform() for each logger, now */
    char **m = calloc(g->n ? g->n : 1, sizeof(*m));
    time_t now = time(NULL);
    for (size_t i = 0; m != NULL && i < g->n; i++) {
        const struct lg *x = g->lgs[i];
        m[i] = ks_logfmt_transform(x->fmt, ev, x->kind == LG_SYSLOG ? NULL : x->hostname,
                                   x->kind == LG_SYSLOG ? NULL : x->tag, now);
    }
    if (m != NULL) {
        g->q[(g->qhead + g->qlen) % g->cap] = m;
        g->qlen++;
        pthread_cond_signal(&g->cond);
    }
    pthread_mutex_unlock(&g->mu);
}

size_t ks_loggers_written(const struct ks_loggers *l)
{
    (void)l;
    return atomic_load(&written_total);
}

void ks_loggers_free(struct ks_loggers *l, int wait_ms)
{
    if (l == NULL)
        return;
    struct gen *g = l->g;
    if (g != NULL)
        atomic_fetch_add(&g->refs, 1);
    ks_loggers_stop(l);
    /* the threads hold references; wait a bit for them to go */
    for (int i = 0; g != NULL && i < wait_ms && atomic_load(&g->refs) > 1; i++) {
        struct timespec ts = {0, 1000000};
        nanosleep(&ts, NULL);
    }
    if (g != NULL)
        gen_unref(g);
    ks_schema_free_array(&ks_logger_config_schema, &l->configs);
    free(l);
}
