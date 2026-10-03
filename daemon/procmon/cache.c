/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/procmon/cache.go and cache_events.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/procmon/cache.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/log.h"
#include "common/strmap.h"
#include "daemon/evloop.h"

struct event_item {
    struct ks_proc *proc;
    int64_t last_seen;
};

struct inode_item {
    char *fd_path;
    int pid;
    int64_t last_seen;
};

struct proc_item {
    char *fd_path;
    char **fds;
    size_t nfds;
    int pid;
    int64_t last_seen;
};

static struct {
    bool initialized;
    struct ks_evloop *loop;
    struct ks_timer *inodes_timer, *events_timer;
    struct ks_strmap events; /* "pid" -> struct event_item */
    struct ks_strmap inodes; /* key -> struct inode_item */
    struct proc_item **pids; /* most recent first */
    size_t npids;
    bool checksums_enabled;
    bool hash_md5, hash_sha1; /* the checksums map */
    struct pending_delete *deletes;
} c;

struct pending_delete {
    int pid;
    struct ks_timer *timer;
    struct pending_delete *next;
};

static void ensure_init(void)
{
    if (c.initialized)
        return;
    ks_strmap_init(&c.events);
    ks_strmap_init(&c.inodes);
    c.initialized = true;
}

int64_t ks_procmon_now(void)
{
    if (c.loop != NULL)
        return ks_evloop_now(c.loop);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static bool exists(const char *path)
{
    struct stat st;
    return !(stat(path, &st) < 0 && errno == ENOENT);
}

static void pid_key(int pid, char *buf, size_t len)
{
    snprintf(buf, len, "%d", pid);
}

/* ---- events cache ----------------------------------------------------- */

static void free_event(void *v)
{
    struct event_item *e = v;
    ks_proc_unref(e->proc);
    free(e);
}

struct ks_proc *ks_events_find(int pid)
{
    char key[16];
    ensure_init();
    pid_key(pid, key, sizeof(key));
    struct event_item *e = ks_strmap_get(&c.events, key);
    /* Upstream refreshes LastSeen on a copy of the item, so lookups never
     * extend its life. */
    return e ? e->proc : NULL;
}

size_t ks_events_len(void)
{
    return c.events.count;
}

void ks_events_update_item(struct ks_proc *p)
{
    char key[16];
    ensure_init();
    if (p->path[0] == '\0')
        return;
    pid_key(p->pid, key, sizeof(key));
    struct event_item *old = ks_strmap_get(&c.events, key);
    /* Don't replace a newer process with an older one. */
    if (old != NULL && strcmp(old->proc->path, p->path) != 0 &&
        old->proc->starttime > p->starttime) {
        ks_trace("skipping out-of-order updateItem: %s -> %s", old->proc->path, p->path);
        return;
    }
    if (old != NULL) {
        if (old->proc != p) {
            ks_proc_unref(old->proc);
            old->proc = ks_proc_ref(p);
        }
        old->last_seen = ks_procmon_now();
        return;
    }
    struct event_item *e = malloc(sizeof(*e));
    if (e == NULL)
        return;
    e->proc = ks_proc_ref(p);
    e->last_seen = ks_procmon_now();
    if (ks_strmap_set(&c.events, key, e, NULL) < 0)
        free_event(e);
}

bool ks_events_compute_checksums(struct ks_proc *p)
{
    if (!c.checksums_enabled ||
        (ks_proc_is_alive(p) && ks_proc_checksums_count(p) > 0))
        return false;
    if (c.hash_md5)
        ks_proc_compute_checksum(p, KS_HASH_MD5);
    if (c.hash_sha1)
        ks_proc_compute_checksum(p, KS_HASH_SHA1);
    return true;
}

void ks_events_add(struct ks_proc *p)
{
    ks_debug("[cache] EventsStore.Add() %d, %s, total: %zu", p->pid, p->path,
             ks_events_len());
    ks_events_update_item(p);
    if (c.checksums_enabled && ks_events_compute_checksums(p))
        ks_events_update_item(p);
}

bool ks_events_needs_update(struct ks_proc *cached, const struct ks_proc *p)
{
    size_t sums = ks_proc_checksums_count(cached);
    /* The PID replaced its parent (exec): systemd, pid 1234 -> curl,
     * pid 1234. */
    if (p != NULL && p->pid == cached->pid && strcmp(p->path, cached->path) != 0)
        return true;
    if (p != NULL && sums > 0 && ks_proc_is_alive(cached))
        return false;
    if (sums == 0)
        return true;
    if (p != NULL && p->ntree == 0)
        return true;
    return cached->ntree == 0;
}

/* ReplaceItem */
static void replace_item(struct ks_proc *old, struct ks_proc *p)
{
    p->ppid = old->pid;
    ks_events_update_item(p);
    if (ks_proc_checksums_count(p) == 0) {
        ks_events_compute_checksums(p);
        ks_events_update_item(p);
    }
    if (old->ntree == 0) {
        ks_proc_get_parent(old);
        ks_proc_build_tree(old);
        ks_events_update_item(old);
    }
    if (p->ntree == 0) {
        ks_proc_unref(p->parent);
        p->parent = ks_proc_ref(old);
        ks_proc_sync(p);
        ks_proc_build_tree(p);
        ks_events_update_item(p);
    }
}

void ks_events_update(struct ks_proc *old, struct ks_proc *p)
{
    ks_debug("[cache Update old] %d in cache -> %s", old->pid, old->path);
    if (p != NULL && p->pid == old->pid && strcmp(p->path, old->path) != 0) {
        replace_item(old, p);
        return;
    }
    bool update_old = false, update = false;
    if (old->ntree == 0) {
        ks_proc_get_parent(old);
        ks_proc_build_tree(old);
        update_old = true;
    }
    if (p != NULL && old->ntree > 0 && p->ntree == 0 && old->pid == p->pid) {
        for (size_t i = 0; i < old->ntree; i++) {
            struct ks_tree_item *t = realloc(p->tree, (p->ntree + 1) * sizeof(*t));
            if (t == NULL)
                break;
            p->tree = t;
            if ((p->tree[p->ntree].path = strdup(old->tree[i].path)) == NULL)
                break;
            p->tree[p->ntree++].pid = old->tree[i].pid;
        }
        update = true;
    }
    if (update_old)
        ks_events_update_item(old);
    if (update)
        ks_events_update_item(p);
}

static void on_delete(void *data)
{
    struct pending_delete *d = data;
    for (struct pending_delete **pp = &c.deletes; *pp; pp = &(*pp)->next)
        if (*pp == d) {
            *pp = d->next;
            break;
        }
    char key[16];
    pid_key(d->pid, key, sizeof(key));
    struct event_item *e = ks_strmap_get(&c.events, key);
    if (e != NULL && !ks_proc_is_alive(e->proc)) {
        ks_trace("[cache delete] deleted %d: %s", d->pid, e->proc->path);
        free_event(ks_strmap_del(&c.events, key));
    }
    free(d);
}

void ks_events_delete(int pid)
{
    if (ks_events_find(pid) == NULL)
        return;
    if (c.loop == NULL) {
        /* No loop to wait on: check right away. */
        char key[16];
        pid_key(pid, key, sizeof(key));
        struct event_item *e = ks_strmap_get(&c.events, key);
        if (e != NULL && !ks_proc_is_alive(e->proc))
            free_event(ks_strmap_del(&c.events, key));
        return;
    }
    struct pending_delete *d = calloc(1, sizeof(*d));
    if (d == NULL)
        return;
    d->pid = pid;
    d->timer = ks_evloop_add_timer(c.loop, KS_EVENTS_EXIT_DELAY_NS, 0, on_delete, d);
    if (d->timer == NULL) {
        free(d);
        return;
    }
    d->next = c.deletes;
    c.deletes = d;
}

static bool old_and_dead(const char *key, void *value, void *ctx)
{
    struct event_item *e = value;
    int64_t now = *(int64_t *)ctx;
    (void)key;
    bool valid = now - e->last_seen < KS_EVENTS_PID_TTL_NS;
    if (!valid && !ks_proc_is_alive(e->proc)) {
        ks_trace("[cache] deleting old item: %d", e->proc->pid);
        free_event(e);
        return true;
    }
    return false;
}

void ks_events_delete_old_items(void)
{
    ensure_init();
    int64_t now = ks_procmon_now();
    ks_debug("[cache] deleting old events, total byPID: %zu", c.events.count);
    ks_strmap_filter(&c.events, old_and_dead, &now);
}

static bool reset_sums(const char *key, void *value, void *ctx)
{
    struct event_item *e = value;
    (void)key;
    if (ctx != NULL)
        ks_proc_reset_checksums(e->proc);
    else if (ks_proc_checksums_count(e->proc) == 0) {
        if (c.hash_md5)
            ks_proc_compute_checksum(e->proc, KS_HASH_MD5);
        if (c.hash_sha1)
            ks_proc_compute_checksum(e->proc, KS_HASH_SHA1);
    }
    return false;
}

void ks_events_set_compute_checksums(bool compute)
{
    ensure_init();
    if (compute == c.checksums_enabled) {
        ks_debug("SetComputeChecksums(), no changes (%d, %d)", c.checksums_enabled, compute);
        return;
    }
    c.checksums_enabled = compute;
    /* Disabled: forget the saved checksums. Enabled: compute the missing
     * ones. */
    ks_strmap_filter(&c.events, reset_sums, compute ? NULL : (void *)1);
}

bool ks_events_get_compute_checksums(void)
{
    return c.checksums_enabled;
}

void ks_events_add_checksum_hash(const char *algo)
{
    if (strcmp(algo, KS_HASH_MD5) == 0)
        c.hash_md5 = true;
    else if (strcmp(algo, KS_HASH_SHA1) == 0)
        c.hash_sha1 = true;
}

void ks_events_del_checksum_hash(const char *algo)
{
    /* Upstream decrements a counter but keeps the key, so the algorithm
     * stays in use: nothing to do. */
    (void)algo;
}

/* ---- inodes cache ----------------------------------------------------- */

static void free_inode(void *v)
{
    struct inode_item *i = v;
    free(i->fd_path);
    free(i);
}

void ks_inodes_add(const char *key, const char *fd_link, int pid)
{
    char exe[64];
    ensure_init();
    if (fd_link == NULL || fd_link[0] == '\0') {
        snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
        fd_link = exe;
    }
    struct inode_item *i = malloc(sizeof(*i));
    if (i == NULL || (i->fd_path = strdup(fd_link)) == NULL) {
        free(i);
        return;
    }
    i->pid = pid;
    i->last_seen = ks_procmon_now();
    void *old;
    if (ks_strmap_set(&c.inodes, key, i, &old) < 0)
        free_inode(i);
    else if (old != NULL)
        free_inode(old);
}

int ks_inodes_get_pid(const char *key)
{
    ensure_init();
    struct inode_item *i = ks_strmap_get(&c.inodes, key);
    if (i == NULL)
        return -1;
    /* the process may be gone by now */
    struct stat st;
    if (lstat(i->fd_path, &st) == 0) {
        i->last_seen = ks_procmon_now();
        return i->pid;
    }
    ks_pids_delete(i->pid);
    i = ks_strmap_del(&c.inodes, key);
    if (i != NULL)
        free_inode(i);
    return -1;
}

static bool inode_of_pid(const char *key, void *value, void *ctx)
{
    struct inode_item *i = value;
    (void)key;
    if (i->pid == *(int *)ctx) {
        free_inode(i);
        return true;
    }
    return false;
}

void ks_inodes_delete_pid(int pid)
{
    ensure_init();
    ks_strmap_filter(&c.inodes, inode_of_pid, &pid);
}

static bool stale_inode(const char *key, void *value, void *ctx)
{
    struct inode_item *i = value;
    int64_t now = *(int64_t *)ctx;
    (void)key;
    /* int(lastSeen.Minutes()) > maxTTL */
    if (!exists(i->fd_path) || (now - i->last_seen) / (60LL * 1000000000) > 3) {
        free_inode(i);
        return true;
    }
    return false;
}

void ks_inodes_cleanup(void)
{
    ensure_init();
    int64_t now = ks_procmon_now();
    ks_strmap_filter(&c.inodes, stale_inode, &now);
}

size_t ks_inodes_len(void)
{
    return c.inodes.count;
}

/* ---- pids cache ------------------------------------------------------- */

void ks_free_names(char **names, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(names[i]);
    free(names);
}

static void free_proc_item(struct proc_item *p)
{
    free(p->fd_path);
    ks_free_names(p->fds, p->nfds);
    free(p);
}

struct name_time {
    char *name;
    int64_t mtime;
};

static int by_time_desc(const void *a, const void *b)
{
    const struct name_time *x = a, *y = b;
    return (x->mtime < y->mtime) - (x->mtime > y->mtime);
}

char **ks_lookup_pid_descriptors(const char *fd_path, size_t *n)
{
    *n = 0;
    DIR *d = opendir(fd_path);
    if (d == NULL)
        return NULL;
    struct name_time *list = NULL;
    size_t count = 0, cap = 0;
    struct dirent *e;
    int dfd = dirfd(d);
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (count == cap) {
            cap = cap ? cap * 2 : 64;
            struct name_time *nl = realloc(list, cap * sizeof(*nl));
            if (nl == NULL)
                break;
            list = nl;
        }
        struct stat st;
        int64_t mt = 0;
        if (fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
            mt = (int64_t)st.st_mtim.tv_sec * 1000000000 + st.st_mtim.tv_nsec;
        if ((list[count].name = strdup(e->d_name)) == NULL)
            break;
        list[count++].mtime = mt;
    }
    closedir(d);
    /* Most recently modified first (sortPidsByTime). */
    if (count > 1)
        qsort(list, count, sizeof(*list), by_time_desc);
    char **names = malloc((count ? count : 1) * sizeof(*names));
    if (names == NULL) {
        for (size_t i = 0; i < count; i++)
            free(list[i].name);
        free(list);
        return NULL;
    }
    for (size_t i = 0; i < count; i++)
        names[i] = list[i].name;
    free(list);
    *n = count;
    return names;
}

size_t ks_pids_len(void)
{
    return c.npids;
}

void ks_pids_add(const char *fd_path, char **fds, size_t nfds, int pid)
{
    for (size_t i = 0; i < c.npids; i++) {
        if (c.pids[i]->pid == pid) {
            c.pids[i]->last_seen = ks_procmon_now();
            return;
        }
    }
    struct proc_item *p = calloc(1, sizeof(*p));
    struct proc_item **np = realloc(c.pids, (c.npids + 1) * sizeof(*np));
    if (p == NULL || np == NULL || (p->fd_path = strdup(fd_path)) == NULL) {
        free(p);
        if (np != NULL)
            c.pids = np;
        return;
    }
    c.pids = np;
    p->fds = calloc(nfds ? nfds : 1, sizeof(*p->fds));
    for (size_t i = 0; p->fds != NULL && i < nfds; i++)
        if ((p->fds[i] = strdup(fds[i])) != NULL)
            p->nfds++;
    p->pid = pid;
    p->last_seen = ks_procmon_now();
    /* setItems(new, old): the new one goes first. */
    memmove(c.pids + 1, c.pids, c.npids * sizeof(*c.pids));
    c.pids[0] = p;
    c.npids++;
}

static void delete_item(size_t pos)
{
    if (pos >= c.npids)
        return;
    free_proc_item(c.pids[pos]);
    memmove(c.pids + pos, c.pids + pos + 1, (c.npids - pos - 1) * sizeof(*c.pids));
    c.npids--;
}

void ks_pids_delete(int pid)
{
    for (size_t i = 0; i < c.npids; i++) {
        if (c.pids[i]->pid == pid) {
            delete_item(i);
            ks_inodes_delete_pid(pid);
            break;
        }
    }
}

static int by_last_seen_desc(const void *a, const void *b)
{
    const struct proc_item *x = *(struct proc_item *const *)a;
    const struct proc_item *y = *(struct proc_item *const *)b;
    return (x->last_seen < y->last_seen) - (x->last_seen > y->last_seen);
}

void ks_pids_sort(int pid)
{
    if (c.npids > 0 && c.pids[0]->pid == pid)
        return;
    /* sort.Slice isn't stable; a stable order is one of its outcomes. */
    if (c.npids > 1)
        qsort(c.pids, c.npids, sizeof(*c.pids), by_last_seen_desc);
}

/* getPidDescriptorsFromCache: returns the index of the descriptor that
 * links to `expect`, moving it to the front. */
static long find_descriptor(struct proc_item *p, const char *key, const char *expect)
{
    for (size_t i = 0; i < p->nfds; i++) {
        char link_path[PATH_MAX], link[PATH_MAX];
        snprintf(link_path, sizeof(link_path), "%s%s", p->fd_path, p->fds[i]);
        ssize_t n = readlink(link_path, link, sizeof(link) - 1);
        if (n < 0)
            continue;
        link[n] = '\0';
        if (strcmp(link, expect) != 0)
            continue;
        if (i > 0) { /* reordering cuts lookups by a factor of 10 */
            char *fd = p->fds[i];
            memmove(p->fds + 1, p->fds, i * sizeof(*p->fds));
            p->fds[0] = fd;
        }
        if (ks_strmap_get(&c.inodes, key) != NULL)
            ks_inodes_add(key, link_path, p->pid);
        return (long)i;
    }
    return -1;
}

int ks_pids_get_pid(const char *key, const char *expect, int *pos)
{
    ensure_init();
    for (size_t n = 0; n < c.npids;) {
        struct proc_item *p = c.pids[n];
        if (find_descriptor(p, key, expect) != -1) {
            p->last_seen = ks_procmon_now();
            *pos = (int)n;
            return p->pid;
        }
        size_t nfds;
        char **fds = ks_lookup_pid_descriptors(p->fd_path, &nfds);
        if (fds == NULL) { /* the process is gone */
            delete_item(n);
            continue;
        }
        ks_free_names(p->fds, p->nfds);
        p->fds = fds;
        p->nfds = nfds;
        if (find_descriptor(p, key, expect) != -1) {
            p->last_seen = ks_procmon_now();
            *pos = (int)n;
            return p->pid;
        }
        n++;
    }
    *pos = -1;
    return -1;
}

/* ---- lifecycle -------------------------------------------------------- */

static void on_inodes_timer(void *data)
{
    (void)data;
    ks_inodes_cleanup();
}

static void on_events_timer(void *data)
{
    (void)data;
    ks_events_delete_old_items();
}

void ks_procmon_cache_init(struct ks_evloop *loop)
{
    ensure_init();
    c.loop = loop;
    if (loop != NULL) {
        c.inodes_timer = ks_evloop_add_timer(loop, KS_INODES_CLEANUP_NS,
                                             KS_INODES_CLEANUP_NS, on_inodes_timer, NULL);
        c.events_timer = ks_evloop_add_timer(loop, KS_EVENTS_SWEEP_NS,
                                             KS_EVENTS_SWEEP_NS, on_events_timer, NULL);
    }
}

void ks_procmon_cache_reset(void)
{
    ensure_init();
    if (c.loop != NULL) {
        ks_evloop_cancel_timer(c.loop, c.inodes_timer);
        ks_evloop_cancel_timer(c.loop, c.events_timer);
    }
    while (c.deletes != NULL) {
        struct pending_delete *d = c.deletes;
        c.deletes = d->next;
        if (c.loop != NULL)
            ks_evloop_cancel_timer(c.loop, d->timer);
        free(d);
    }
    ks_strmap_clear(&c.events, free_event);
    ks_strmap_clear(&c.inodes, free_inode);
    while (c.npids > 0)
        delete_item(c.npids - 1);
    free(c.pids);
    c.pids = NULL;
    c.loop = NULL;
    c.inodes_timer = c.events_timer = NULL;
    c.checksums_enabled = c.hash_md5 = c.hash_sha1 = false;
}
