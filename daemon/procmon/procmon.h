/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Process monitor, "proc" method: from a connection to the process that
 * owns it. Port of upstream daemon/procmon/find.go, parse.go,
 * activepids.go and the process lookup of conman/connection.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_procmon_result holds a reference to `proc`; release it
 * with ks_procmon_result_clear().
 */
#ifndef KS_DAEMON_PROCMON_PROCMON_H
#define KS_DAEMON_PROCMON_PROCMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/netaddr.h"
#include "daemon/procmon/cache.h"
#include "daemon/procmon/process.h"

struct ks_evloop;

#define KS_PROCMON_METHOD_PROC "proc"
#define KS_PROCMON_METHOD_AUDIT "audit"
#define KS_PROCMON_METHOD_EBPF "ebpf"

/* monitor.Init for the proc method: cache cleanups on `loop` and, if the
 * kernel allows it (needs CAP_NET_ADMIN), the exec/exit event listener.
 * Returns 0; a missing event listener is only logged. */
int ks_procmon_init(struct ks_evloop *loop);
void ks_procmon_end(void);
/* Whether exec/exit events are being received. */
bool ks_procmon_events_running(void);

/* GetPIDFromINode: the PID owning socket `inode` (caches, then /proc).
 * `key` identifies the connection ("inode src sport dst dport"). */
int ks_procmon_pid_from_inode(int64_t inode, const char *key);

/* lookupPidInProc: walks /proc (most recently started first). */
int ks_procmon_lookup_pid_in_proc(const char *procfs, const char *expect,
                                  const char *key);

/* GetInodeFromNetstat */
bool ks_procmon_inode_from_netstat(const char *proto, const struct ks_ip *src,
                                   unsigned sport, const struct ks_ip *dst,
                                   unsigned dport, int64_t *inode);

/* FindProcess: from the cache, or read from /proc and cached. With
 * `intercept_unknown` and pid < 0, an empty process. NULL if it can't be
 * read. Returns a new reference. */
struct ks_proc *ks_procmon_find_process(int pid, bool intercept_unknown);

/* What newConnectionImpl learns about a connection's owner. */
struct ks_procmon_result {
    int pid;            /* -1: unknown */
    int64_t uid;        /* Entry.UserId */
    int64_t inode;      /* Entry.INode */
    struct ks_proc *proc;
};

/* The "proc" method lookup of conman.newConnectionImpl: sock_diag, else
 * /proc/net, for the inodes; then the PID; then the process. `nfq_uid` is
 * the packet's UID from netfilter (0xffffffff: unknown). Returns 0, or -1
 * if the process couldn't be found (upstream drops such connections). */
int ks_procmon_resolve(const char *proto, const struct ks_ip *src, unsigned sport,
                       const struct ks_ip *dst, unsigned dport, uint32_t nfq_uid,
                       bool intercept_unknown, struct ks_procmon_result *out);
void ks_procmon_result_clear(struct ks_procmon_result *r);

/* MonitorProcEvents handlers, called by the event listener (and tests). */
void ks_procmon_on_exec(int pid, int tgid);
void ks_procmon_on_exit(int pid);

#endif
