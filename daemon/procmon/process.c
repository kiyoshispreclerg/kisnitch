/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/procmon/process.go and details.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/procmon/process.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/hash.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/procmon/cache.h"

#define PROC_FILE_MAX (16u * 1024 * 1024)
/* Guards against parent loops (PID reuse races). */
#define MAX_PARENTS 128

/* ---- small helpers ---------------------------------------------------- */

static char *xstrdup(const char *s)
{
    return strdup(s != NULL ? s : "");
}

static void set_str(char **dst, const char *src)
{
    char *dup = xstrdup(src);
    if (dup == NULL)
        return; /* keep the old value on OOM */
    free(*dst);
    *dst = dup;
}

static void path_of(const struct ks_proc *p, const char *name, char *buf, size_t len)
{
    snprintf(buf, len, "%s/%s", p->dir, name);
}

/* os.Readlink */
static char *read_link(const char *path)
{
    char buf[PATH_MAX + 1];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n < 0)
        return NULL;
    buf[n] = '\0';
    return strdup(buf);
}

static bool exists(const char *path)
{
    struct stat st;
    return !(stat(path, &st) < 0 && errno == ENOENT);
}

/* core.Trim */
static void trim_span(const char **s, size_t *n, const char *set)
{
    while (*n > 0 && strchr(set, (*s)[0]) != NULL && (*s)[0] != '\0') {
        (*s)++;
        (*n)--;
    }
    while (*n > 0 && strchr(set, (*s)[*n - 1]) != NULL && (*s)[*n - 1] != '\0')
        (*n)--;
}

/* ---- lifecycle -------------------------------------------------------- */

struct ks_proc *ks_proc_new_empty(int pid, const char *comm)
{
    struct ks_proc *p = calloc(1, sizeof(*p));
    if (p == NULL)
        return NULL;
    p->refs = 1;
    p->pid = pid;
    /* time.Now().UnixNano(): wall clock, as the cache compares them. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    p->starttime = (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
    if ((p->comm = xstrdup(comm)) == NULL || (p->path = xstrdup("")) == NULL ||
        (p->root = xstrdup("")) == NULL || (p->real_path = xstrdup("")) == NULL ||
        (p->cwd = xstrdup("")) == NULL) {
        ks_proc_unref(p);
        return NULL;
    }
    snprintf(p->dir, sizeof(p->dir), "/proc/%d", pid);
    ks_proc_sync(p);
    return p;
}

struct ks_proc *ks_proc_ref(struct ks_proc *p)
{
    if (p != NULL)
        p->refs++;
    return p;
}

static void free_args(struct ks_proc *p)
{
    for (size_t i = 0; i < p->nargs; i++)
        free(p->args[i]);
    free(p->args);
    p->args = NULL;
    p->nargs = 0;
}

static void free_env(struct ks_proc *p)
{
    for (size_t i = 0; i < p->nenv; i++) {
        free((char *)p->env[i].name);
        free((char *)p->env[i].value);
    }
    free(p->env);
    p->env = NULL;
    p->nenv = 0;
}

static void free_tree(struct ks_proc *p)
{
    for (size_t i = 0; i < p->ntree; i++)
        free(p->tree[i].path);
    free(p->tree);
    p->tree = NULL;
    p->ntree = 0;
}

void ks_proc_unref(struct ks_proc *p)
{
    /* Iterative, so a long chain of parents can't blow the stack. */
    while (p != NULL && --p->refs == 0) {
        struct ks_proc *parent = p->parent;
        free(p->comm);
        free(p->path);
        free(p->root);
        free(p->real_path);
        free(p->cwd);
        free_args(p);
        free_env(p);
        free(p->checksum_md5);
        free(p->checksum_sha1);
        free_tree(p);
        free(p);
        p = parent;
    }
}

void ks_proc_sync(struct ks_proc *p)
{
    p->view.pid = p->pid;
    p->view.path = p->path;
    p->view.args = (const char *const *)p->args;
    p->view.nargs = p->nargs;
    p->view.env = p->env;
    p->view.nenv = p->nenv;
    p->view.checksum_md5 = p->checksum_md5;
    p->view.checksum_sha1 = p->checksum_sha1;
    p->view.parent = p->parent ? &p->parent->view : NULL;
}

bool ks_proc_is_alive(const struct ks_proc *p)
{
    return exists(p->dir);
}

static bool is_abs(const char *path)
{
    /* core.IsAbsPath indexes path[0], which panics on ""; empty isn't
     * absolute here. */
    return path[0] == '/';
}

/* ---- reading /proc ---------------------------------------------------- */

void ks_proc_read_root(struct ks_proc *p)
{
    char path[64];
    if (p->root[0] != '\0')
        return;
    path_of(p, "root", path, sizeof(path));
    char *root = read_link(path);
    if (root != NULL) {
        free(p->root);
        p->root = root;
        return;
    }
    set_str(&p->root, "/");
}

static void clean_path(struct ks_proc *p, int depth);

/* SetPath, carrying the CleanPath/ReadPath recursion depth. */
static void set_path(struct ks_proc *p, const char *path, int depth)
{
    set_str(&p->path, path);
    clean_path(p, depth);
    ks_proc_read_root(p);
    /* The path inside the process' root: /proc/<pid>/root/<path>. */
    char real[PATH_MAX * 2];
    snprintf(real, sizeof(real), "%s/root%s", p->dir, p->path);
    set_str(&p->real_path, exists(real) ? real : p->path);
    /* /proc/<pid>/root is any directory the process chroot'ed to. */
    size_t rl = strlen(p->root);
    if (strcmp(p->root, "/") != 0 && strncmp(p->path, p->root, rl) != 0) {
        char chroot[PATH_MAX * 2];
        snprintf(chroot, sizeof(chroot), "%s%s", p->root, p->path);
        if (exists(chroot))
            set_str(&p->path, chroot);
    }
}

static int read_path(struct ks_proc *p, int depth)
{
    char path[64];
    if (p->path[0] != '\0' && is_abs(p->path))
        return 0; /* avoid rereading the path */

    path_of(p, "exe", path, sizeof(path));
    char *link = read_link(path);
    int ret = 0;
    if (link == NULL) {
        ret = -1;
    } else {
        set_path(p, link, depth + 1);
        free(link);
    }

    if (p->path[0] == '\0') {
        /* Possibly a kernel task: /proc/<pid>/maps is empty. */
        char maps[64], err[128];
        size_t len;
        path_of(p, "maps", maps, sizeof(maps));
        char *data = ks_read_file(maps, PROC_FILE_MAX, &len, err, sizeof(err));
        if (data != NULL && len == 0) {
            set_str(&p->path, KS_KERNEL_CONNECTION);
            char **args = realloc(p->args, (p->nargs + 1) * sizeof(*args));
            if (args != NULL) {
                p->args = args;
                p->args[p->nargs] = xstrdup(p->comm);
                if (p->args[p->nargs] != NULL)
                    p->nargs++;
            }
        } else {
            set_str(&p->path, p->comm);
        }
        free(data);
    }
    ks_proc_sync(p);
    return ret;
}

int ks_proc_read_path(struct ks_proc *p)
{
    return read_path(p, 0);
}

static void clean_path(struct ks_proc *p, int depth)
{
    char path[64];
    /* /proc/self/exe or /proc/<pid>/fd/<n>: resolve, or fall back to the
     * command line or the name. */
    if (strncmp(p->path, "/proc", 5) == 0) {
        path_of(p, "exe", path, sizeof(path));
        char *link = read_link(path);
        if (link != NULL) {
            free(p->path);
            p->path = link;
            return;
        }
        if (p->nargs > 0 && p->args[0][0] != '\0') {
            set_str(&p->path, p->args[0]);
            return;
        }
        set_str(&p->path, p->comm);
    }

    size_t n = strlen(p->path);
    if (n >= 10 && strcmp(p->path + n - 10, " (deleted)") == 0)
        p->path[n - 10] = '\0';

    /* Relative paths come from the kernel sometimes; the path must be
     * absolute. */
    if (!is_abs(p->path) && depth < 8)
        read_path(p, depth);
}

void ks_proc_clean_path(struct ks_proc *p)
{
    clean_path(p, 0);
    ks_proc_sync(p);
}

void ks_proc_set_path(struct ks_proc *p, const char *path)
{
    set_path(p, path, 0);
    ks_proc_sync(p);
}

void ks_proc_clean_args(struct ks_proc *p)
{
    if (p->nargs > 0 && strcmp(p->args[0], KS_PROC_SELF_EXE) == 0) {
        set_str(&p->args[0], p->path);
        ks_proc_sync(p);
    }
}

void ks_proc_read_cmdline(struct ks_proc *p)
{
    char path[64], err[128];
    size_t len;
    if (p->nargs > 0)
        return;
    path_of(p, "cmdline", path, sizeof(path));
    char *data = ks_read_file(path, PROC_FILE_MAX, &len, err, sizeof(err));
    if (data == NULL || len == 0) {
        free(data);
        return;
    }
    /* NULs become spaces, then split by spaces: arguments with spaces end
     * up split too, as upstream. */
    for (size_t i = 0; i < len; i++)
        if (data[i] == '\0')
            data[i] = ' ';
    const char *s = data, *end = data + len;
    while (s <= end) {
        const char *sp = memchr(s, ' ', (size_t)(end - s));
        size_t n = sp ? (size_t)(sp - s) : (size_t)(end - s);
        const char *arg = s;
        s = sp ? sp + 1 : end + 1;
        trim_span(&arg, &n, "\r\n\t ");
        if (n == 0)
            continue;
        char **args = realloc(p->args, (p->nargs + 1) * sizeof(*args));
        if (args == NULL)
            break;
        p->args = args;
        if ((p->args[p->nargs] = strndup(arg, n)) == NULL)
            break;
        p->nargs++;
    }
    free(data);
    ks_proc_clean_args(p);
    ks_proc_sync(p);
}

void ks_proc_read_comm(struct ks_proc *p)
{
    char path[64], err[128];
    size_t len;
    if (p->comm[0] != '\0')
        return;
    path_of(p, "comm", path, sizeof(path));
    char *data = ks_read_file(path, PROC_FILE_MAX, &len, err, sizeof(err));
    if (data == NULL)
        return;
    const char *s = data;
    trim_span(&s, &len, "\r\n\t ");
    char *comm = strndup(s, len);
    if (comm != NULL) {
        free(p->comm);
        p->comm = comm;
    }
    free(data);
}

void ks_proc_read_cwd(struct ks_proc *p)
{
    char path[64];
    if (p->cwd[0] != '\0')
        return;
    path_of(p, "cwd", path, sizeof(path));
    char *link = read_link(path);
    if (link != NULL) {
        free(p->cwd);
        p->cwd = link;
    }
}

void ks_proc_read_env_file(struct ks_proc *p, const char *path)
{
    char err[128];
    size_t len;
    char *raw = ks_read_file(path, PROC_FILE_MAX, &len, err, sizeof(err));
    if (raw == NULL)
        return;
    /* bytes.Trim(raw, "\r\n\t"), split by NUL, "key=value" by the first '='.
     * Like the Go map, a repeated name keeps the last value. */
    const char *s = raw;
    trim_span(&s, &len, "\r\n\t");
    struct ks_env_var *env = NULL;
    size_t nenv = 0, cap = 0;
    const char *end = s + len;
    while (s <= end) {
        const char *nul = memchr(s, '\0', (size_t)(end - s));
        size_t n = nul ? (size_t)(nul - s) : (size_t)(end - s);
        const char *var = s;
        s = nul ? nul + 1 : end + 1;
        const char *eq = memchr(var, '=', n);
        if (eq == NULL)
            continue;
        char *name = strndup(var, (size_t)(eq - var));
        char *value = strndup(eq + 1, n - (size_t)(eq - var) - 1);
        if (name == NULL || value == NULL) {
            free(name);
            free(value);
            break;
        }
        size_t i;
        for (i = 0; i < nenv; i++)
            if (strcmp(env[i].name, name) == 0)
                break;
        if (i < nenv) {
            free(name);
            free((char *)env[i].value);
            env[i].value = value;
            continue;
        }
        if (nenv == cap) {
            cap = cap ? cap * 2 : 32;
            struct ks_env_var *ne = realloc(env, cap * sizeof(*ne));
            if (ne == NULL) {
                free(name);
                free(value);
                break;
            }
            env = ne;
        }
        env[nenv].name = name;
        env[nenv].value = value;
        nenv++;
    }
    free(raw);
    free_env(p);
    p->env = env;
    p->nenv = nenv;
    ks_proc_sync(p);
}

void ks_proc_read_env(struct ks_proc *p)
{
    char path[64];
    path_of(p, "environ", path, sizeof(path));
    ks_proc_read_env_file(p, path);
}

const char *ks_proc_getenv(const struct ks_proc *p, const char *name)
{
    for (size_t i = 0; i < p->nenv; i++)
        if (strcmp(p->env[i].name, name) == 0)
            return p->env[i].value;
    return NULL;
}

void ks_proc_read_ppid(struct ks_proc *p)
{
    char path[64], err[128];
    size_t len;
    path_of(p, "stat", path, sizeof(path));
    char *data = ks_read_file(path, PROC_FILE_MAX, &len, err, sizeof(err));
    p->ppid = 0;
    if (data == NULL)
        return;
    /* The name can contain ')': parse after the last one. */
    char *after = NULL;
    for (char *c = data; c < data + len; c++)
        if (*c == ')')
            after = c + 1;
    char state[16];
    int ppid;
    if (sscanf(after ? after : data, "%15s %d", state, &ppid) == 2 && ppid != 0)
        p->ppid = ppid;
    free(data);
}

int ks_proc_get_details(struct ks_proc *p)
{
    if (p->pid == getpid())
        return 0;
    /* If /proc/<pid> doesn't exist, the process exited or it's a kernel
     * connection: there's nothing to show without a name. */
    if (p->path[0] == '\0' && !ks_proc_is_alive(p)) {
        ks_debug("PID can't be read /proc/ %d %s", p->pid, p->comm);
        if (p->comm[0] == '\0')
            return -1;
    }
    if (ks_proc_read_path(p) < 0) {
        ks_debug("GetInfo() path can't be read: %s", p->path);
        return -1;
    }
    ks_proc_read_cmdline(p);
    ks_proc_read_comm(p);
    ks_proc_read_cwd(p);
    /* the environment is needed by the rules */
    ks_proc_read_env(p);
    ks_proc_sync(p);
    return 0;
}

/* ---- parents ---------------------------------------------------------- */

static void get_parent(struct ks_proc *p, int depth)
{
    if (depth > MAX_PARENTS)
        return;
    if (p->parent != NULL && p->pid == 1)
        return;
    ks_proc_read_ppid(p);
    if (p->ppid == 0)
        return;

    struct ks_proc *cached = ks_events_find(p->ppid);
    struct ks_proc *parent;
    if (cached != NULL && cached != p) {
        parent = ks_proc_ref(cached);
    } else {
        parent = ks_proc_new_empty(p->ppid, "");
        if (parent == NULL)
            return;
        ks_proc_read_path(parent);
    }
    ks_proc_unref(p->parent);
    p->parent = parent;
    ks_proc_sync(p);
    get_parent(parent, depth + 1);
}

void ks_proc_get_parent(struct ks_proc *p)
{
    get_parent(p, 0);
}

static int tree_add(struct ks_proc *p, const char *path, int pid)
{
    struct ks_tree_item *t = realloc(p->tree, (p->ntree + 1) * sizeof(*t));
    if (t == NULL)
        return -1;
    p->tree = t;
    if ((p->tree[p->ntree].path = xstrdup(path)) == NULL)
        return -1;
    p->tree[p->ntree].pid = pid;
    p->ntree++;
    return 0;
}

void ks_proc_build_tree(struct ks_proc *p)
{
    if (p->ntree > 0 && p->tree[p->ntree - 1].pid == 1)
        return;
    /* This process, then its parents from the closest one. */
    if (tree_add(p, p->path, p->pid) < 0)
        return;
    int n = 0;
    for (struct ks_proc *pp = p->parent; pp != NULL && n < MAX_PARENTS; pp = pp->parent, n++)
        if (tree_add(p, pp->path, pp->pid) < 0)
            return;
}

/* ---- checksums -------------------------------------------------------- */

size_t ks_proc_checksums_count(const struct ks_proc *p)
{
    return (p->checksum_md5 != NULL) + (p->checksum_sha1 != NULL);
}

void ks_proc_reset_checksums(struct ks_proc *p)
{
    free(p->checksum_md5);
    free(p->checksum_sha1);
    p->checksum_md5 = p->checksum_sha1 = NULL;
    ks_proc_sync(p);
}

/* Hashes a file. Returns 0 and the hex digest. */
static int hash_file(const char *path, bool md5, char *hex)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct ks_md5 m;
    struct ks_sha1 s;
    if (md5)
        ks_md5_init(&m);
    else
        ks_sha1_init(&s);
    char buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        if (md5)
            ks_md5_update(&m, buf, (size_t)n);
        else
            ks_sha1_update(&s, buf, (size_t)n);
    }
    close(fd);
    uint8_t digest[20];
    if (md5) {
        ks_md5_final(&m, digest);
        ks_hex_encode(digest, 16, hex);
    } else {
        ks_sha1_final(&s, digest);
        ks_hex_encode(digest, 20, hex);
    }
    return 0;
}

void ks_proc_compute_checksum(struct ks_proc *p, const char *algo)
{
    bool md5;
    if (strcmp(algo, KS_HASH_MD5) == 0)
        md5 = true;
    else if (strcmp(algo, KS_HASH_SHA1) == 0)
        md5 = false;
    else {
        ks_debug("Unknown hashing algorithm: %s", algo);
        return;
    }
    if (p->path[0] == '\0' || strcmp(p->path, KS_KERNEL_CONNECTION) == 0)
        return;
    char **slot = md5 ? &p->checksum_md5 : &p->checksum_sha1;
    if (*slot != NULL && (*slot)[0] != '\0')
        return; /* already hashed */

    /* The running image first (it matches even if the file on disk was
     * replaced), then the path inside the process' root, then the path.
     * Upstream falls back to dumping the process memory, which hashes an
     * empty buffer (see docs/UPSTREAM.md); that step is skipped. */
    char exe[64];
    path_of(p, "exe", exe, sizeof(exe));
    const char *paths[3] = {exe, p->real_path, p->path};
    char hex[41];
    for (int i = 0; i < 3; i++) {
        if (hash_file(paths[i], md5, hex) == 0) {
            set_str(slot, hex);
            break;
        }
        ks_debug("[hashing %s] Unable to open path: %s", algo, paths[i]);
    }
    ks_proc_sync(p);
}
