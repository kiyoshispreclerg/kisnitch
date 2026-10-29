/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/downloader (main.go, downloader.go,
 * config.go, utils.go).
 *
 * The downloads run on a thread with libcurl (built with CURL=1), all the
 * lists at once like upstream's goroutines; the loop gets the results
 * through a pipe. Each list is written to a temporary file next to it and
 * renamed when the download succeeds (upstream writes over the old file
 * without truncating it).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _GNU_SOURCE /* pipe2 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef KS_HAVE_CURL
#include <curl/curl.h>
#endif

#include "cJSON.h"
#include "common/duration.h"
#include "common/json_schema.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/tasks/disk.h"
#include "daemon/tasks/iocscanner.h" /* NotifyOpts: the same struct in both */

/* base.DOWNLOADER */
#define DOWNLOADER_ID 9003
#define DEFAULT_INTERVAL "6h"
#define DEFAULT_TIMEOUT "5s"
#define SUCCESS_MSG "[blocklists] lists updated"

/* downloader.UrlOptions and DownloaderConfig */
struct url_opts {
    char *name, *remote, *local_file;
    bool enabled; /* not used upstream: every list is downloaded */
};
struct dl_config {
    char *interval, *timeout;
    struct ks_array urls;
    struct ks_ioc_notify notify;
};

static const struct ks_schema_field url_fields[] = {
    KS_FIELD(struct url_opts, "Name", KS_T_STRING, name),
    KS_FIELD(struct url_opts, "Remote", KS_T_STRING, remote),
    KS_FIELD(struct url_opts, "LocalFile", KS_T_STRING, local_file),
    KS_FIELD(struct url_opts, "Enabled", KS_T_BOOL, enabled),
};
static const struct ks_schema url_schema =
    KS_SCHEMA("downloader.UrlOptions", struct url_opts, url_fields);
static const struct ks_schema_field dl_fields[] = {
    KS_FIELD(struct dl_config, "Interval", KS_T_STRING, interval),
    KS_FIELD(struct dl_config, "Timeout", KS_T_STRING, timeout),
    KS_FIELD_SUB(struct dl_config, "Urls", KS_T_ARRAY, urls, url_schema),
    KS_FIELD_SUB(struct dl_config, "Notify", KS_T_STRUCT, notify, ks_ioc_notify_schema),
};
static const struct ks_schema dl_schema =
    KS_SCHEMA("downloader.DownloaderConfig", struct dl_config, dl_fields);

/* DownProgress */
struct job {
    const char *url, *local; /* point into the config */
    bool ok;
    long long bytes;
    char err[256];
};

struct dl {
    struct ks_task *task;
    struct ks_evloop *loop;
    struct dl_config cfg;
    int64_t timeout_ns;
    struct job *jobs; /* Urls: remote -> local file, one per remote */
    size_t njobs;
    struct ks_timer *ticker;
    pthread_t thread;
    bool busy, pending;
    int pipe[2];
    atomic_bool cancel;
};

bool ks_downloader_available(void)
{
#ifdef KS_HAVE_CURL
    return true;
#else
    return false;
#endif
}

/* ---- the downloads (thread) ------------------------------------------- */

#ifdef KS_HAVE_CURL
struct xfer {
    struct job *job;
    FILE *out;
    char tmp[4096];
    CURL *easy;
};

static int on_progress(void *p, curl_off_t a, curl_off_t b, curl_off_t c, curl_off_t d)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return atomic_load(&((struct dl *)p)->cancel) ? 1 : 0;
}

static void *download_all(void *data)
{
    struct dl *d = data;
    CURLM *multi = curl_multi_init();
    struct xfer *x = calloc(d->njobs, sizeof(*x));
    for (size_t i = 0; i < d->njobs; i++) {
        struct job *j = &d->jobs[i];
        j->ok = false;
        j->bytes = 0;
        j->err[0] = '\0';
        if (multi == NULL || x == NULL) {
            snprintf(j->err, sizeof(j->err), "out of memory");
            continue;
        }
        x[i].job = j;
        ks_debug("[DownloadManager] downloadFile: %s -> %s", j->url, j->local);
        snprintf(x[i].tmp, sizeof(x[i].tmp), "%s.XXXXXX", j->local);
        int fd = mkstemp(x[i].tmp);
        if (fd < 0 || (x[i].out = fdopen(fd, "w")) == NULL) {
            snprintf(j->err, sizeof(j->err), "open %s: %s", j->local, strerror(errno));
            ks_warning("[DownloadManager] downloadFile, Create() error: %s, %s -> %s", j->err,
                       j->url, j->local);
            if (fd >= 0) {
                close(fd);
                unlink(x[i].tmp);
            }
            x[i].tmp[0] = '\0';
            continue;
        }
        CURL *e = curl_easy_init();
        if (e == NULL) {
            snprintf(j->err, sizeof(j->err), "out of memory");
            continue;
        }
        x[i].easy = e;
        curl_easy_setopt(e, CURLOPT_URL, j->url);
        curl_easy_setopt(e, CURLOPT_WRITEDATA, x[i].out);
        /* http.Client: follows up to 10 redirects, gzip, proxies from the
         * environment, Timeout covers the whole request (0: none) */
        curl_easy_setopt(e, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(e, CURLOPT_MAXREDIRS, 10L);
        curl_easy_setopt(e, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(e, CURLOPT_TIMEOUT_MS, (long)(d->timeout_ns / KS_MILLISECOND));
        curl_easy_setopt(e, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(e, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(e, CURLOPT_XFERINFOFUNCTION, on_progress);
        curl_easy_setopt(e, CURLOPT_XFERINFODATA, d);
        curl_easy_setopt(e, CURLOPT_PRIVATE, &x[i]);
        curl_multi_add_handle(multi, e);
    }
    int running = 1;
    while (multi != NULL && running > 0) {
        if (curl_multi_perform(multi, &running) != CURLM_OK)
            break;
        if (running > 0)
            curl_multi_poll(multi, NULL, 0, 200, NULL);
    }
    CURLMsg *m;
    int left;
    while (multi != NULL && (m = curl_multi_info_read(multi, &left)) != NULL) {
        if (m->msg != CURLMSG_DONE)
            continue;
        char *priv = NULL;
        curl_easy_getinfo(m->easy_handle, CURLINFO_PRIVATE, &priv);
        struct xfer *xf = (struct xfer *)(void *)priv;
        struct job *j = xf->job;
        long code = 0;
        curl_easy_getinfo(m->easy_handle, CURLINFO_RESPONSE_CODE, &code);
        fflush(xf->out);
        long long n = (long long)ftello(xf->out);
        if (m->data.result != CURLE_OK) {
            snprintf(j->err, sizeof(j->err), "Get \"%s\": %s", j->url,
                     curl_easy_strerror(m->data.result));
            ks_warning("[DownloadManager] downloadFile, http connect() error: %s, %s -> %s",
                       j->err, j->url, j->local);
        } else if (code != 200) {
            /* upstream reports this one with a nil error */
            ks_warning("[DownloadManager] http status error (%ld): %%!s(<nil>), %s -> %s", code,
                       j->url, j->local);
        } else if (n == 0) {
            ks_warning("[DownloadManager] 0 bytes (list empty/moved?): %%!s(<nil>), %s -> %s",
                       j->url, j->local);
            snprintf(j->err, sizeof(j->err), "list is empty");
        } else {
            j->ok = true;
            j->bytes = n;
        }
    }
    for (size_t i = 0; x != NULL && i < d->njobs; i++) {
        if (x[i].easy != NULL) {
            curl_multi_remove_handle(multi, x[i].easy);
            curl_easy_cleanup(x[i].easy);
        }
        if (x[i].out != NULL)
            fclose(x[i].out);
        if (x[i].tmp[0] == '\0')
            continue;
        if (x[i].job->ok && rename(x[i].tmp, x[i].job->local) < 0) {
            snprintf(x[i].job->err, sizeof(x[i].job->err), "rename %s: %s", x[i].job->local,
                     strerror(errno));
            x[i].job->ok = false;
        }
        if (!x[i].job->ok)
            unlink(x[i].tmp);
    }
    free(x);
    if (multi != NULL)
        curl_multi_cleanup(multi);
    char c = 1;
    ssize_t w = write(d->pipe[1], &c, 1);
    (void)w;
    return NULL;
}
#endif

/* ---- the task (loop) -------------------------------------------------- */

static void start_downloads(struct dl *d);

static void on_done(int fd, uint32_t events, void *data)
{
    (void)events;
    struct dl *d = data;
    char c;
    while (read(fd, &c, 1) > 0)
        ;
    if (!d->busy)
        return;
    pthread_join(d->thread, NULL);
    d->busy = false;
    size_t errors = 0, rlen = 1;
    for (size_t i = 0; i < d->njobs; i++) {
        ks_debug("[Downloader] finished: %lld bytes, %s", d->jobs[i].bytes, d->jobs[i].url);
        if (!d->jobs[i].ok) {
            errors++;
            rlen += strlen(d->jobs[i].url) + 2;
        }
    }
    char *results = calloc(1, rlen);
    for (size_t i = 0; results != NULL && i < d->njobs; i++) {
        if (!d->jobs[i].ok) {
            strncat(results, ", ", rlen - strlen(results) - 1);
            strncat(results, d->jobs[i].url, rlen - strlen(results) - 1);
        }
    }
    if (d->cfg.notify.enabled && results != NULL) {
        size_t mlen = strlen(SUCCESS_MSG) + strlen("\n\nErrors:\n") + rlen + 1;
        char *msg = malloc(mlen);
        if (msg != NULL) {
            /* "\n\nErrors:\n" goes before the ", url" list */
            snprintf(msg, mlen, "%s%s%s", SUCCESS_MSG, errors > 0 ? "\n\nErrors:\n" : "", results);
            ks_task_emit(d->task, msg, NULL);
            free(msg);
        }
    }
    ks_debug("[Downloader] finished (%zu): %s", d->njobs, results ? results : "");
    free(results);
    if (d->pending) {
        d->pending = false;
        start_downloads(d);
    }
}

static void start_downloads(struct dl *d)
{
#ifdef KS_HAVE_CURL
    if (d->busy) {
        d->pending = true; /* a ticker keeps one tick */
        return;
    }
    ks_debug("[Downloader] urls: %zu", d->njobs);
    d->busy = pthread_create(&d->thread, NULL, download_all, d) == 0;
    if (!d->busy)
        ks_error("[Downloader] could not start the downloads: %s", strerror(errno));
#else
    (void)d;
#endif
}

static void on_tick(void *data)
{
    start_downloads(data);
}

static int dl_start(struct ks_task *t, char *err, size_t errlen)
{
    struct dl *d = t->priv;
    d->task = t;
    d->loop = ks_task_loop(t);
    if (!ks_downloader_available()) {
        snprintf(err, errlen, "the downloader needs a build with CURL=1");
        return -1;
    }
    int64_t interval;
    char perr[256];
    if (ks_parse_duration(d->cfg.interval[0] ? d->cfg.interval : DEFAULT_INTERVAL, &interval,
                          perr, sizeof(perr)) < 0 ||
        interval <= 0) {
        /* time.NewTicker(0) panics upstream */
        ks_warning("[Downloader] Invalid interval: %s", perr);
        snprintf(err, errlen, "invalid interval: %s", d->cfg.interval);
        return -1;
    }
    if (ks_parse_duration(d->cfg.timeout[0] ? d->cfg.timeout : DEFAULT_TIMEOUT, &d->timeout_ns,
                          perr, sizeof(perr)) < 0) {
        ks_warning("[Downloader] Invalid timeout");
        d->timeout_ns = 0;
    }
    /* loadUrls: create the lists' directories; a map, so one entry per
     * remote (the last one) */
    d->jobs = calloc(d->cfg.urls.len ? d->cfg.urls.len : 1, sizeof(*d->jobs));
    if (d->jobs == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    for (size_t i = 0; i < d->cfg.urls.len; i++) {
        const struct url_opts *u = KS_ARRAY_ITEM(d->cfg.urls, struct url_opts, i);
        char dir[4096];
        snprintf(dir, sizeof(dir), "%s", u->local_file);
        char *slash = strrchr(dir, '/');
        if (slash == NULL)
            snprintf(dir, sizeof(dir), ".");
        else if (slash == dir)
            dir[1] = '\0';
        else
            *slash = '\0';
        struct stat st;
        if (stat(dir, &st) < 0) {
            char cmd_dir[4096];
            snprintf(cmd_dir, sizeof(cmd_dir), "%s", dir);
            for (char *p = cmd_dir + 1; *p; p++)
                if (*p == '/') {
                    *p = '\0';
                    mkdir(cmd_dir, 0700);
                    *p = '/';
                }
            if (mkdir(cmd_dir, 0700) < 0 && errno != EEXIST) {
                ks_warning("[Downloader] url %s localdir create error %s: %s", u->name, dir,
                           strerror(errno));
                continue;
            }
            ks_debug("[Downloader] localdir created %s", dir);
        }
        size_t k;
        for (k = 0; k < d->njobs; k++)
            if (strcmp(d->jobs[k].url, u->remote) == 0)
                break;
        d->jobs[k].url = u->remote;
        d->jobs[k].local = u->local_file;
        if (k == d->njobs)
            d->njobs++;
    }
    if (pipe2(d->pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
        snprintf(err, errlen, "pipe: %s", strerror(errno));
        d->pipe[0] = d->pipe[1] = -1;
        return -1;
    }
    if (ks_evloop_add_fd(d->loop, d->pipe[0], EPOLLIN, on_done, d) < 0) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
#ifdef KS_HAVE_CURL
    static bool curl_ready;
    if (!curl_ready)
        curl_ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
#endif
    /* the first downloads right away, then at every tick */
    d->ticker = ks_evloop_add_timer(d->loop, interval, interval, on_tick, d);
    start_downloads(d);
    return 0;
}

static void dl_free(void *priv)
{
    struct dl *d = priv;
    if (d == NULL)
        return;
    ks_debug("Downloader.Stop() %s", KS_TASK_DOWNLOADER);
    if (d->busy) {
        atomic_store(&d->cancel, true);
        pthread_join(d->thread, NULL);
    }
    if (d->ticker != NULL)
        ks_evloop_cancel_timer(d->loop, d->ticker);
    if (d->pipe[0] >= 0) {
        if (d->loop != NULL)
            ks_evloop_del_fd(d->loop, d->pipe[0]);
        close(d->pipe[0]);
        close(d->pipe[1]);
    }
    free(d->jobs);
    ks_schema_free(&dl_schema, &d->cfg);
    free(d);
}

static const struct ks_task_ops dl_ops = {dl_start, NULL, dl_free};

struct ks_task *ks_downloader_new(const char *name, const cJSON *data)
{
    struct dl *d = calloc(1, sizeof(*d));
    if (d == NULL)
        return NULL;
    d->pipe[0] = d->pipe[1] = -1;
    atomic_init(&d->cancel, false);
    /* a missing "data" is a nil map: json.Marshal gives null, a zero config */
    char err[512];
    cJSON *empty = cJSON_CreateObject();
    if (data == NULL || ks_schema_decode(&dl_schema, data, &d->cfg, err, sizeof(err)) < 0) {
        if (data != NULL)
            ks_warning("Downloader config warning: %s", err);
        if (empty == NULL || ks_schema_decode(&dl_schema, empty, &d->cfg, err, sizeof(err)) < 0) {
            cJSON_Delete(empty);
            free(d);
            return NULL;
        }
    }
    cJSON_Delete(empty);
    struct ks_task *t = ks_task_new(name, &dl_ops, d);
    if (t != NULL)
        t->id = DOWNLOADER_ID;
    return t;
}
