/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/evloop.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

struct watcher {
    int fd;
    ks_fd_cb cb;
    void *data;
    bool dead; /* removed during dispatch; freed afterwards */
    struct watcher *next;
};

struct ks_timer {
    int64_t deadline;
    int64_t interval;
    ks_timer_cb cb;
    void *data;
    bool cancelled; /* cancelled from its own callback */
    struct ks_timer *next;
};

struct ks_evloop {
    int epfd;
    int tfd;
    struct watcher *watchers;
    struct ks_timer *timers; /* sorted by deadline */
    struct ks_timer *firing; /* timer whose callback is running */
    int dispatching;
    bool stop;
    ks_clock_fn clock;
    void *clock_ctx;
};

static int64_t monotonic_ns(void *ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int64_t ks_evloop_now(struct ks_evloop *loop)
{
    return loop->clock(loop->clock_ctx);
}

void ks_evloop_set_clock(struct ks_evloop *loop, ks_clock_fn fn, void *ctx)
{
    loop->clock = fn != NULL ? fn : monotonic_ns;
    loop->clock_ctx = ctx;
}

struct ks_evloop *ks_evloop_new(void)
{
    struct ks_evloop *loop = calloc(1, sizeof(*loop));
    if (loop == NULL)
        return NULL;
    loop->clock = monotonic_ns;
    loop->epfd = epoll_create1(EPOLL_CLOEXEC);
    loop->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (loop->epfd < 0 || loop->tfd < 0)
        goto fail;
    struct epoll_event ev = {.events = EPOLLIN, .data.ptr = NULL};
    if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->tfd, &ev) < 0)
        goto fail;
    return loop;

fail:
    if (loop->epfd >= 0)
        close(loop->epfd);
    if (loop->tfd >= 0)
        close(loop->tfd);
    free(loop);
    return NULL;
}

void ks_evloop_free(struct ks_evloop *loop)
{
    if (loop == NULL)
        return;
    while (loop->watchers != NULL) {
        struct watcher *w = loop->watchers;
        loop->watchers = w->next;
        free(w);
    }
    while (loop->timers != NULL) {
        struct ks_timer *t = loop->timers;
        loop->timers = t->next;
        free(t);
    }
    close(loop->epfd);
    close(loop->tfd);
    free(loop);
}

/* ---- fds -------------------------------------------------------------- */

int ks_evloop_add_fd(struct ks_evloop *loop, int fd, uint32_t events,
                     ks_fd_cb cb, void *data)
{
    struct watcher *w = calloc(1, sizeof(*w));
    if (w == NULL)
        return -1;
    w->fd = fd;
    w->cb = cb;
    w->data = data;
    struct epoll_event ev = {.events = events, .data.ptr = w};
    if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        free(w);
        return -1;
    }
    w->next = loop->watchers;
    loop->watchers = w;
    return 0;
}

static void reap_watchers(struct ks_evloop *loop)
{
    struct watcher **pp = &loop->watchers;
    while (*pp != NULL) {
        struct watcher *w = *pp;
        if (w->dead) {
            *pp = w->next;
            free(w);
        } else {
            pp = &w->next;
        }
    }
}

void ks_evloop_del_fd(struct ks_evloop *loop, int fd)
{
    for (struct watcher *w = loop->watchers; w != NULL; w = w->next) {
        if (w->fd == fd && !w->dead) {
            epoll_ctl(loop->epfd, EPOLL_CTL_DEL, fd, NULL);
            w->dead = true;
            break;
        }
    }
    if (!loop->dispatching)
        reap_watchers(loop);
}

/* ---- timers ----------------------------------------------------------- */

static void arm(struct ks_evloop *loop)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    if (loop->timers != NULL) {
        int64_t d = loop->timers->deadline;
        if (d <= 0)
            d = 1; /* zero would disarm the timerfd */
        its.it_value.tv_sec = (time_t)(d / 1000000000);
        its.it_value.tv_nsec = (long)(d % 1000000000);
    }
    timerfd_settime(loop->tfd, TFD_TIMER_ABSTIME, &its, NULL);
}

static void insert_timer(struct ks_evloop *loop, struct ks_timer *t)
{
    struct ks_timer **pp = &loop->timers;
    while (*pp != NULL && (*pp)->deadline <= t->deadline)
        pp = &(*pp)->next;
    t->next = *pp;
    *pp = t;
}

struct ks_timer *ks_evloop_add_timer(struct ks_evloop *loop, int64_t delay_ns,
                                     int64_t interval_ns, ks_timer_cb cb,
                                     void *data)
{
    struct ks_timer *t = calloc(1, sizeof(*t));
    if (t == NULL)
        return NULL;
    t->deadline = ks_evloop_now(loop) + (delay_ns > 0 ? delay_ns : 0);
    t->interval = interval_ns;
    t->cb = cb;
    t->data = data;
    insert_timer(loop, t);
    arm(loop);
    return t;
}

void ks_evloop_cancel_timer(struct ks_evloop *loop, struct ks_timer *t)
{
    if (t == NULL)
        return;
    if (t == loop->firing) {
        t->cancelled = true;
        return;
    }
    for (struct ks_timer **pp = &loop->timers; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == t) {
            *pp = t->next;
            free(t);
            break;
        }
    }
    arm(loop);
}

int ks_evloop_timer_count(const struct ks_evloop *loop)
{
    int n = 0;
    for (const struct ks_timer *t = loop->timers; t != NULL; t = t->next)
        n++;
    return n;
}

int ks_evloop_fire_due(struct ks_evloop *loop)
{
    int fired = 0;
    int64_t now = ks_evloop_now(loop);

    /* Pop one timer at a time: callbacks may add or cancel timers. */
    while (loop->timers != NULL && loop->timers->deadline <= now) {
        struct ks_timer *t = loop->timers;
        loop->timers = t->next;
        t->next = NULL;

        loop->firing = t;
        t->cb(t->data);
        loop->firing = NULL;
        fired++;

        if (t->interval > 0 && !t->cancelled) {
            t->deadline += t->interval;
            if (t->deadline <= now) /* don't try to catch up */
                t->deadline = now + t->interval;
            insert_timer(loop, t);
        } else {
            free(t);
        }
    }
    arm(loop);
    return fired;
}

/* ---- dispatch --------------------------------------------------------- */

int ks_evloop_run_once(struct ks_evloop *loop, int timeout_ms)
{
    struct epoll_event evs[32];
    int n = epoll_wait(loop->epfd, evs, 32, timeout_ms);
    if (n < 0)
        return errno == EINTR ? 0 : -1;

    int ran = 0;
    loop->dispatching++;
    for (int i = 0; i < n; i++) {
        struct watcher *w = evs[i].data.ptr;
        if (w == NULL) { /* the timerfd */
            uint64_t expirations;
            if (read(loop->tfd, &expirations, sizeof(expirations)) < 0) {
                /* EAGAIN: already consumed; nothing to do */
            }
            ran += ks_evloop_fire_due(loop);
            continue;
        }
        if (w->dead)
            continue;
        w->cb(w->fd, evs[i].events, w->data);
        ran++;
    }
    loop->dispatching--;
    if (!loop->dispatching)
        reap_watchers(loop);
    return ran;
}

int ks_evloop_run(struct ks_evloop *loop)
{
    loop->stop = false;
    while (!loop->stop)
        if (ks_evloop_run_once(loop, -1) < 0)
            return -1;
    return 0;
}

void ks_evloop_stop(struct ks_evloop *loop)
{
    loop->stop = true;
}
