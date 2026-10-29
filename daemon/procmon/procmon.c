/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/procmon/find.go, parse.go, activepids.go and the
 * process lookup of conman/connection.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/procmon/procmon.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/netstat.h"
#include "daemon/procmon/audit.h"
#include "daemon/procmon/events.h"
#include "daemon/sockdiag.h"

#define MAX_INODES 64

/* ---- /proc walking (find.go) ------------------------------------------ */

struct pid_time {
    int pid;
    int64_t mtime;
};

static int by_time_desc(const void *a, const void *b)
{
    const struct pid_time *x = a, *y = b;
    return (x->mtime < y->mtime) - (x->mtime > y->mtime);
}

/* getProcPids: numeric directories, most recently modified first. */
static int *get_proc_pids(const char *procfs, size_t *n)
{
    *n = 0;
    DIR *d = opendir(procfs);
    if (d == NULL)
        return NULL;
    int dfd = dirfd(d);
    struct pid_time *list = NULL;
    size_t count = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char *end;
        long pid = strtol(e->d_name, &end, 10);
        if (*end != '\0' || end == e->d_name || pid < 0 || pid > INT_MAX)
            continue;
        struct stat st;
        if (fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0 || !S_ISDIR(st.st_mode))
            continue;
        if (count == cap) {
            cap = cap ? cap * 2 : 512;
            struct pid_time *nl = realloc(list, cap * sizeof(*nl));
            if (nl == NULL)
                break;
            list = nl;
        }
        list[count].pid = (int)pid;
        list[count++].mtime = (int64_t)st.st_mtim.tv_sec * 1000000000 + st.st_mtim.tv_nsec;
    }
    closedir(d);
    if (count > 1)
        qsort(list, count, sizeof(*list), by_time_desc);
    int *pids = malloc((count ? count : 1) * sizeof(*pids));
    for (size_t i = 0; pids != NULL && i < count; i++)
        pids[i] = list[i].pid;
    free(list);
    *n = pids ? count : 0;
    return pids;
}

/* inodeFound */
static bool inode_found(const char *procfs, const char *expect, const char *key,
                        int pid)
{
    char fd_path[PATH_MAX];
    snprintf(fd_path, sizeof(fd_path), "%s%d/fd/", procfs, pid);
    size_t nfds;
    char **fds = ks_lookup_pid_descriptors(fd_path, &nfds);
    if (fds == NULL)
        return false;
    bool found = false;
    for (size_t i = 0; i < nfds && !found; i++) {
        char link_path[PATH_MAX], link[PATH_MAX];
        snprintf(link_path, sizeof(link_path), "%s%s", fd_path, fds[i]);
        ssize_t n = readlink(link_path, link, sizeof(link) - 1);
        if (n < 0)
            continue;
        link[n] = '\0';
        if (strcmp(link, expect) == 0) {
            ks_inodes_add(key, link_path, pid);
            ks_pids_add(fd_path, fds, nfds, pid);
            found = true;
        }
    }
    ks_free_names(fds, nfds);
    return found;
}

int ks_procmon_lookup_pid_in_proc(const char *procfs, const char *expect,
                                  const char *key)
{
    size_t n;
    int *pids = get_proc_pids(procfs, &n);
    int found = -1;
    for (size_t i = 0; i < n && found == -1; i++)
        if (inode_found(procfs, expect, key, pids[i]))
            found = pids[i];
    free(pids);
    return found;
}

/* ---- parse.go --------------------------------------------------------- */

bool ks_procmon_inode_from_netstat(const char *proto, const struct ks_ip *src,
                                   unsigned sport, const struct ks_ip *dst,
                                   unsigned dport, int64_t *inode)
{
    struct ks_netstat_entry e;
    ks_netstat_find(proto, src, sport, dst, dport, &e);
    if (e.inode > 0) {
        ks_debug("connection found in netstat: inode %lld", (long long)e.inode);
        *inode = e.inode;
        return true;
    }
    ks_debug("<== no inodes found for this connection");
    return false;
}

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int ks_procmon_pid_from_inode(int64_t inode, const char *key)
{
    if (inode <= 0)
        return -1;
    int64_t start = now_ns();
    char expect[48];
    snprintf(expect, sizeof(expect), "socket:[%lld]", (long long)inode);

    int pid = ks_inodes_get_pid(key);
    if (pid != -1) {
        ks_debug("Inode found in cache: %lld us, pid %d, inode %lld",
                 (long long)(now_ns() - start) / 1000, pid, (long long)inode);
        return pid;
    }
    int pos;
    pid = ks_pids_get_pid(key, expect, &pos);
    if (pid != -1) {
        ks_debug("Socket found in known pids, pid: %d, inode: %lld, pos: %d",
                 pid, (long long)inode, pos);
        ks_pids_sort(pid);
        ks_inodes_add(key, "", pid);
        return pid;
    }
    if (strcmp(ks_procmon_get_method(), KS_PROCMON_METHOD_AUDIT) == 0) {
        /* getPIDFromAuditEvents: the PIDs, then the parents, of the
         * processes that opened sockets */
        for (int parent = 0; parent < 2; parent++) {
            for (size_t i = 0; i < ks_audit_count(); i++) {
                const struct ks_audit_event *ev = ks_audit_event_at(i);
                int apid = parent ? ev->ppid : ev->pid;
                if (inode_found("/proc/", expect, key, apid)) {
                    ks_debug("PID found via audit events: %lld us, position: %zu",
                             (long long)(now_ns() - start) / 1000, i);
                    return apid;
                }
            }
        }
    }
    pid = ks_procmon_lookup_pid_in_proc("/proc/", expect, key);
    ks_debug("new pid lookup took (%d): %lld us", pid,
             (long long)(now_ns() - start) / 1000);
    return pid;
}

struct ks_proc *ks_procmon_find_process(int pid, bool intercept_unknown)
{
    if (intercept_unknown && pid < 0)
        return ks_proc_new_empty(0, "");

    struct ks_proc *cached = ks_events_find(pid);
    if (cached != NULL)
        return ks_proc_ref(cached);

    struct ks_proc *p = ks_proc_new_empty(pid, "");
    if (p == NULL)
        return NULL;
    if (ks_proc_get_details(p) < 0) {
        ks_debug("[%d] FindProcess() error: Unable to get process information", pid);
        ks_proc_unref(p);
        return NULL;
    }
    ks_events_add(p);
    return p;
}

/* ---- conman.newConnectionImpl (proc method) --------------------------- */

void ks_procmon_result_clear(struct ks_procmon_result *r)
{
    ks_proc_unref(r->proc);
    memset(r, 0, sizeof(*r));
}

int ks_procmon_resolve(const char *proto, const struct ks_ip *src, unsigned sport,
                       const struct ks_ip *dst, unsigned dport, uint32_t nfq_uid,
                       bool intercept_unknown, struct ks_procmon_result *out)
{
    memset(out, 0, sizeof(*out));
    out->pid = -1;
    out->uid = -1;
    out->inode = -1;

    /* 0. uid and inodes via netlink; 1. else /proc/net; 2. PID by inode. */
    int64_t uid, inodes[MAX_INODES];
    size_t n = ks_socket_info(proto, src, sport, dst, dport, &uid, inodes, MAX_INODES);
    if (n == 0 && ks_procmon_inode_from_netstat(proto, src, sport, dst, dport, &inodes[0]))
        n = 1;

    char sip[KS_IP_STRLEN], dip[KS_IP_STRLEN];
    ks_ip_string(src, sip, sizeof(sip));
    ks_ip_string(dst, dip, sizeof(dip));
    int pid = -1;
    for (size_t i = 0; i < n; i++) {
        /* fmt.Sprint(inode, srcIP, srcPort, dstIP, dstPort) */
        char key[160];
        snprintf(key, sizeof(key), "%lld %s %u %s %u", (long long)inodes[i], sip,
                 sport, dip, dport);
        pid = ks_procmon_pid_from_inode(inodes[i], key);
        if (pid != -1) {
            ks_debug("[%zu] PID found %d [%lld]", i, pid, (long long)inodes[i]);
            out->inode = inodes[i];
            break;
        }
    }
    out->pid = pid;

    /* Our own connections (e.g. to the UI): an empty process with our PID. */
    if (pid == getpid()) {
        out->proc = ks_proc_new_empty(pid, "");
        return out->proc ? 0 : -1;
    }

    if (nfq_uid != 0xffffffffu)
        uid = nfq_uid;
    out->uid = uid;

    out->proc = ks_procmon_find_process(pid, intercept_unknown);
    if (out->proc == NULL) {
        ks_debug("Could not find process by its pid %d for: %s %u -> %s:%u",
                 pid, sip, sport, dip, dport);
        return -1;
    }
    return 0;
}

/* ---- exec / exit events (activepids.go) ------------------------------- */

void ks_procmon_on_exec(int pid, int tgid)
{
    /* NewProcessWithParent + GetParent + BuildTree: the exec'd binary with
     * its real parents. (Upstream first builds the parent from the TGID,
     * which GetParent then replaces.) */
    struct ks_proc *p = ks_proc_new_empty(pid, "");
    if (p == NULL)
        return;
    p->ppid = tgid;
    ks_proc_get_details(p);
    ks_proc_get_parent(p);
    ks_proc_build_tree(p);
    ks_debug("[procmon exec event] pid:%d tgid:%d %s, %s", pid, tgid, p->comm, p->path);

    struct ks_proc *cached = ks_events_find(pid);
    if (cached != NULL) {
        if (ks_events_needs_update(cached, p)) {
            ks_proc_ref(cached);
            ks_events_update(cached, p);
            ks_proc_unref(cached);
        }
    } else {
        ks_events_add(p);
    }
    ks_proc_unref(p);
}

void ks_procmon_on_exit(int pid)
{
    struct ks_proc *cached = ks_events_find(pid);
    if (cached != NULL && !ks_proc_is_alive(cached))
        ks_events_delete(pid);
}

/* ---- monitor.Init ----------------------------------------------------- */

/* procmon.monitorMethod ("" until the first ReconfigureMonitorMethod) and
 * monitor.cacheMonitorsRunning. */
static char monitor_method[16];
static char audit_socket[108]; /* Audit.AudispSocketPath */
static bool cache_monitors_running;
static struct ks_evloop *monitor_loop;

const char *ks_procmon_get_method(void)
{
    return monitor_method;
}

static void set_method(const char *m)
{
    snprintf(monitor_method, sizeof(monitor_method), "%s", m);
}

/* monitor.startProcMonitors() */
static void start_proc_monitors(void)
{
    if (monitor_loop != NULL && !ks_proc_events_running() &&
        ks_proc_events_start(monitor_loop) < 0)
        ks_warning("unable to start netlink.ProcEventMonitor: process exec/exit "
                   "events won't be tracked (needs root)");
}

/* monitor.Init() */
int ks_procmon_monitor_init(struct ks_evloop *loop, char *err, size_t errlen)
{
    int what = KS_MONITOR_NO_ERROR;
    monitor_loop = loop;
    if (!cache_monitors_running) {
        ks_procmon_cache_init(loop);
        cache_monitors_running = true;
    }
    if (strcmp(monitor_method, KS_PROCMON_METHOD_EBPF) == 0) {
        what = KS_MONITOR_EBPF_ERR;
        snprintf(err, errlen, "the ebpf method is not available yet (EBPF=1, phase 9)");
        ks_warning("error starting ebpf monitor method: %s", err);
    } else if (strcmp(monitor_method, KS_PROCMON_METHOD_AUDIT) == 0) {
        if (ks_audit_start(loop, audit_socket, err, errlen) == 0) {
            /* upstream returns an AuditdErr kind here too, which makes
             * ReconfigureMonitorMethod roll the method back to proc with
             * the reader still running: audit never takes effect */
            ks_info("Process monitor method audit");
            return KS_MONITOR_NO_ERROR;
        }
        what = KS_MONITOR_AUDITD_ERR;
        ks_warning("error starting audit monitor method: %s", err);
    }
    start_proc_monitors();
    /* if any of the above methods have failed, fallback to proc */
    ks_info("Process monitor method /proc");
    set_method(KS_PROCMON_METHOD_PROC);
    return what;
}

/* monitor.End(): stops the exec/exit listener; the caches stay. */
void ks_procmon_monitor_end(void)
{
    ks_debug("monitor.End()");
    ks_proc_events_stop();
    if (strcmp(monitor_method, KS_PROCMON_METHOD_AUDIT) == 0)
        ks_audit_stop();
}

/* monitor.ReconfigureMonitorMethod() */
int ks_procmon_reconfigure(struct ks_evloop *loop, const char *method, const char *audit_path,
                           char *err, size_t errlen)
{
    snprintf(audit_socket, sizeof(audit_socket), "%s", audit_path != NULL ? audit_path : "");
    char old[sizeof(monitor_method)];
    snprintf(old, sizeof(old), "%s", monitor_method[0] ? monitor_method
                                                         : KS_PROCMON_METHOD_PROC);
    ks_procmon_monitor_end();
    set_method(method);
    /* if the new monitor method fails to start, rollback the change */
    int what = ks_procmon_monitor_init(loop, err, errlen);
    if (what > KS_MONITOR_NO_ERROR) {
        ks_error("Reconf() -> Init() error: %s", err);
        set_method(old);
    }
    return what;
}

int ks_procmon_init(struct ks_evloop *loop)
{
    char err[128];
    set_method(KS_PROCMON_METHOD_PROC);
    ks_procmon_monitor_init(loop, err, sizeof(err));
    return 0;
}

void ks_procmon_end(void)
{
    ks_proc_events_stop();
    ks_audit_stop();
    ks_procmon_cache_reset();
    cache_monitors_running = false;
    monitor_loop = NULL;
    monitor_method[0] = '\0';
}

bool ks_procmon_events_running(void)
{
    return ks_proc_events_running();
}
