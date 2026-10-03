/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Process monitor caches. Port of upstream daemon/procmon/cache.go and
 * cache_events.go:
 *
 *  - inodes: "inode src sport dst dport" -> PID, for connections retried by
 *    the same process. Entries unused for 3 minutes, or whose fd is gone,
 *    are dropped every 2 minutes.
 *  - pids: processes that made connections, most recent first, with the
 *    list of their descriptors, searched before walking all of /proc.
 *  - events (EventsStore): PID -> process details. Exited processes are
 *    dropped 2 s after their exit event, or by the sweep every 10 s once
 *    they're 20 s old.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the events cache holds a reference to each process; functions
 * returning a struct ks_proc * return a borrowed pointer (take a reference
 * to keep it). All state is global, like upstream's; single-threaded.
 */
#ifndef KS_DAEMON_PROCMON_CACHE_H
#define KS_DAEMON_PROCMON_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "daemon/procmon/process.h"

struct ks_evloop;

#define KS_INODES_MAX_TTL_NS (3LL * 60 * 1000000000)     /* maxTTL */
#define KS_INODES_CLEANUP_NS (2LL * 60 * 1000000000)
#define KS_EVENTS_PID_TTL_NS (20LL * 1000000000)         /* pidTTL */
#define KS_EVENTS_SWEEP_NS (10LL * 1000000000)
#define KS_EVENTS_EXIT_DELAY_NS (2LL * 1000000000)       /* exitDelay */

/* Starts the periodic cleanups on `loop`; the clock is the loop's. Without
 * it (NULL), time is CLOCK_MONOTONIC and nothing is cleaned up by itself. */
void ks_procmon_cache_init(struct ks_evloop *loop);
/* Empties every cache and stops the timers. */
void ks_procmon_cache_reset(void);
/* Nanoseconds, from the loop's clock when there is one. */
int64_t ks_procmon_now(void);

/* ---- events cache (EventsStore) ---- */

/* IsInStoreByPID */
struct ks_proc *ks_events_find(int pid);
/* Add: stores the process and computes its checksums if enabled. */
void ks_events_add(struct ks_proc *p);
/* UpdateItem: stores the process unless its path is empty, or the cached
 * one has another path and is newer. */
void ks_events_update_item(struct ks_proc *p);
/* needsUpdate and Update, for exec events. */
bool ks_events_needs_update(struct ks_proc *cached, const struct ks_proc *p);
void ks_events_update(struct ks_proc *old, struct ks_proc *p);
/* Delete: drops the PID after the exit delay, if it's no longer alive. */
void ks_events_delete(int pid);
/* DeleteOldItems */
void ks_events_delete_old_items(void);
size_t ks_events_len(void);

void ks_events_set_compute_checksums(bool compute);
bool ks_events_get_compute_checksums(void);
void ks_events_add_checksum_hash(const char *algo);
void ks_events_del_checksum_hash(const char *algo);
/* ComputeChecksums: returns true if it (re)computed them. */
bool ks_events_compute_checksums(struct ks_proc *p);

/* ---- inodes cache ---- */

void ks_inodes_add(const char *key, const char *fd_link, int pid);
/* getPid: -1 if unknown or if the fd went away (then the PID is also
 * dropped from the pids cache). */
int ks_inodes_get_pid(const char *key);
void ks_inodes_delete_pid(int pid);
void ks_inodes_cleanup(void);
size_t ks_inodes_len(void);

/* ---- pids cache ---- */

/* add: the process' descriptor names (copied). */
void ks_pids_add(const char *fd_path, char **fds, size_t nfds, int pid);
/* getPid: searches the cached processes' descriptors for `expect`
 * ("socket:[<inode>]"), refreshing their lists; dead processes are dropped.
 * Returns the PID and its position, or -1. */
int ks_pids_get_pid(const char *key, const char *expect, int *pos);
void ks_pids_sort(int pid);
void ks_pids_delete(int pid);
size_t ks_pids_len(void);

/* lookupPidDescriptors: names in `fd_path`, most recently modified first.
 * Returns NULL if the directory can't be read; free with ks_free_names(). */
char **ks_lookup_pid_descriptors(const char *fd_path, size_t *n);
void ks_free_names(char **names, size_t n);

#endif
