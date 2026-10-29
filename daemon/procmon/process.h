/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A process read from /proc. Port of upstream daemon/procmon/process.go and
 * details.go (the parts the "proc" monitor method uses).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_proc is reference counted (ks_proc_ref/unref). It owns
 * its strings and holds a reference to its parent. `view` is what the rules
 * engine sees; its pointers point into the process and stay valid while a
 * reference is held. Not thread-safe.
 */
#ifndef KS_DAEMON_PROCMON_PROCESS_H
#define KS_DAEMON_PROCMON_PROCESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "daemon/conn.h"

#define KS_KERNEL_CONNECTION "Kernel connection"
#define KS_PROC_SELF_EXE "/proc/self/exe"
#define KS_HASH_MD5 "process.hash.md5"
#define KS_HASH_SHA1 "process.hash.sha1"

/* An entry of the process tree: the process, then its parents. */
struct ks_tree_item {
    char *path;
    int pid;
};

/* procDescriptors: an entry of /proc/<pid>/fd. */
struct ks_proc_fd {
    char *name;    /* Name */
    char *symlink; /* SymLink */
    int64_t size;  /* Size */
    int64_t mtime_sec; /* ModTime; KS_GO_ZERO_TIME if the target can't be lstat'ed */
    long mtime_nsec;
};

/* What GetExtraInfo reads (only the "pid-monitor" task does). Each field
 * keeps its last value when its file can't be read, as upstream. */
struct ks_proc_extra {
    int64_t statm[6]; /* Statm: Size, Resident, Shared, Text, Lib, Data (bytes) */
    int64_t statm_dt; /* Statm.Dt */
    int64_t io[6];    /* IOStats: RChar, WChar, SyscallRead, SyscallWrite, ReadBytes, WriteBytes */
    char *status, *stat, *stack, *maps; /* Status, Stat, Stack, Maps (NULL: "") */
    struct ks_proc_fd *fds; /* Descriptors (NULL with has_fds false: null) */
    size_t nfds;
    bool has_fds;
};

struct ks_proc {
    int refs;
    struct ks_process view; /* for the rules engine; see ks_proc_sync() */

    int pid;          /* ID */
    int ppid;         /* PPID */
    int64_t starttime; /* Starttime: wall-clock creation time (ns), as upstream */
    char *comm;       /* Comm */
    char *path;       /* Path */
    char *root;       /* Root */
    char *real_path;  /* RealPath */
    char *cwd;        /* CWD */
    char **args;      /* Args */
    size_t nargs;
    struct ks_env_var *env; /* Env (names and values owned) */
    size_t nenv;
    char *checksum_md5;  /* Checksums[process.hash.md5], NULL if absent */
    char *checksum_sha1; /* Checksums[process.hash.sha1] */
    struct ks_proc *parent;
    struct ks_tree_item *tree; /* Tree */
    size_t ntree;
    struct ks_proc_extra *extra; /* owned; NULL until ks_proc_get_extra_info() */
    char dir[32]; /* "/proc/<pid>" */
};

/* NewProcessEmpty: no details read yet. NULL on OOM. */
struct ks_proc *ks_proc_new_empty(int pid, const char *comm);
struct ks_proc *ks_proc_ref(struct ks_proc *p);
void ks_proc_unref(struct ks_proc *p);

/* Refreshes p->view from the other fields. Call after changing them. */
void ks_proc_sync(struct ks_proc *p);

/* GetDetails: path, cmdline, comm, cwd and environment. Our own PID is
 * skipped (returns 0 with nothing read), as upstream. -1 if the process
 * can't be read. */
int ks_proc_get_details(struct ks_proc *p);

int ks_proc_read_path(struct ks_proc *p);   /* ReadPath */
void ks_proc_set_path(struct ks_proc *p, const char *path); /* SetPath */
void ks_proc_clean_path(struct ks_proc *p); /* CleanPath */
void ks_proc_read_cmdline(struct ks_proc *p);
void ks_proc_clean_args(struct ks_proc *p);
void ks_proc_read_comm(struct ks_proc *p);
void ks_proc_read_cwd(struct ks_proc *p);
void ks_proc_read_env(struct ks_proc *p);
/* ReadEnv from another file (for tests). */
void ks_proc_read_env_file(struct ks_proc *p, const char *path);
void ks_proc_read_ppid(struct ks_proc *p);
void ks_proc_read_root(struct ks_proc *p);

/* GetParent: the chain of parents, taken from the events cache when
 * possible (see cache.h). */
void ks_proc_get_parent(struct ks_proc *p);
/* BuildTree */
void ks_proc_build_tree(struct ks_proc *p);

/* IsAlive: /proc/<pid> exists. */
bool ks_proc_is_alive(const struct ks_proc *p);

/* ComputeChecksum for KS_HASH_MD5 or KS_HASH_SHA1: hashes /proc/<pid>/exe,
 * else the real path, else the path. */
void ks_proc_compute_checksum(struct ks_proc *p, const char *algo);
size_t ks_proc_checksums_count(const struct ks_proc *p);
void ks_proc_reset_checksums(struct ks_proc *p);

/* Looks up an environment variable (NULL if absent). */
const char *ks_proc_getenv(const struct ks_proc *p, const char *name);

/* A copy of `p` (strings, arguments, environment, checksums, tree; the
 * parent is shared by reference), like the struct copy upstream's
 * PIDMonitor makes of a cached process. NULL on OOM. */
struct ks_proc *ks_proc_clone(const struct ks_proc *p);

/* GetExtraInfo: environment, descriptors, I/O, status, stat, stack, maps
 * and statm. Reads relative to `procfs` ("/proc" normally). */
void ks_proc_get_extra_info(struct ks_proc *p);
void ks_proc_get_extra_info_at(struct ks_proc *p, const char *procfs);

/* json.Marshal(p), parents included. Returns a malloc'd string owned by
 * the caller, NULL on OOM. The cJSON forms are owned by the caller;
 * ks_proc_zero_cjson() is a zero Process{}. */
char *ks_proc_json(const struct ks_proc *p);
struct cJSON;
struct cJSON *ks_proc_to_cjson(const struct ks_proc *p);
struct cJSON *ks_proc_zero_cjson(void);

#endif
