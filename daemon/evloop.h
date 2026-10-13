/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The daemon's single-threaded event loop (docs/PORTING.md section 4):
 * epoll for file descriptors plus one timerfd multiplexing every timer.
 *
 * Callbacks run on the loop's thread and may add or remove fds and timers,
 * including their own.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the loop owns its fd watchers and timers; a struct ks_timer pointer
 * stays valid until the timer is cancelled or, for one-shot timers, until its
 * callback returns. File descriptors are never closed by the loop.
 */
#ifndef KS_DAEMON_EVLOOP_H
#define KS_DAEMON_EVLOOP_H

#include <stdbool.h>
#include <stdint.h>

struct ks_evloop;
struct ks_timer;

typedef void (*ks_fd_cb)(int fd, uint32_t events, void *data);
typedef void (*ks_timer_cb)(void *data);
/* Returns the current time in nanoseconds (CLOCK_MONOTONIC by default). */
typedef int64_t (*ks_clock_fn)(void *ctx);

struct ks_evloop *ks_evloop_new(void);
/* Cancels every timer and drops every watcher. */
void ks_evloop_free(struct ks_evloop *loop);

/* Watches `fd` for `events` (EPOLLIN, ...). One watcher per fd. */
int ks_evloop_add_fd(struct ks_evloop *loop, int fd, uint32_t events,
                     ks_fd_cb cb, void *data);
void ks_evloop_del_fd(struct ks_evloop *loop, int fd);
/* Changes the events a watched fd waits for. */
int ks_evloop_mod_fd(struct ks_evloop *loop, int fd, uint32_t events);

/* Fires `cb` after `delay_ns`, then every `interval_ns` if it's > 0.
 * Returns NULL on OOM. */
struct ks_timer *ks_evloop_add_timer(struct ks_evloop *loop, int64_t delay_ns,
                                     int64_t interval_ns, ks_timer_cb cb,
                                     void *data);
void ks_evloop_cancel_timer(struct ks_evloop *loop, struct ks_timer *t);

/* Waits up to `timeout_ms` (-1: forever) and dispatches what is ready.
 * Returns the number of callbacks run, or -1 on error. */
int ks_evloop_run_once(struct ks_evloop *loop, int timeout_ms);

/* Runs until ks_evloop_stop(). */
int ks_evloop_run(struct ks_evloop *loop);
void ks_evloop_stop(struct ks_evloop *loop);

int64_t ks_evloop_now(struct ks_evloop *loop);

/* Tests: replace the clock, then fire due timers explicitly with
 * ks_evloop_fire_due() instead of waiting. */
void ks_evloop_set_clock(struct ks_evloop *loop, ks_clock_fn fn, void *ctx);
int ks_evloop_fire_due(struct ks_evloop *loop);

/* Number of pending timers (for tests and leak checks). */
int ks_evloop_timer_count(const struct ks_evloop *loop);

#endif
