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
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "common/hash.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/dns/cache.h"
#include "daemon/procmon/cache.h"
#include "daemon/sockdiag.h"

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

static void free_extra(struct ks_proc_extra *x)
{
    if (x == NULL)
        return;
    free(x->status);
    free(x->stat);
    free(x->stack);
    free(x->maps);
    for (size_t i = 0; i < x->nfds; i++) {
        free(x->fds[i].name);
        free(x->fds[i].symlink);
    }
    free(x->fds);
    free(x);
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
        free_extra(p->extra);
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

/* ---- copies ----------------------------------------------------------- */

struct ks_proc *ks_proc_clone(const struct ks_proc *p)
{
    struct ks_proc *c = ks_proc_new_empty(p->pid, p->comm);
    if (c == NULL)
        return NULL;
    c->ppid = p->ppid;
    c->starttime = p->starttime;
    set_str(&c->path, p->path);
    set_str(&c->root, p->root);
    set_str(&c->real_path, p->real_path);
    set_str(&c->cwd, p->cwd);
    bool oom = false;
    if (p->nargs > 0) {
        if ((c->args = calloc(p->nargs, sizeof(*c->args))) == NULL)
            oom = true;
        for (size_t i = 0; !oom && i < p->nargs; i++, c->nargs++)
            if ((c->args[i] = strdup(p->args[i])) == NULL)
                oom = true;
    }
    if (!oom && p->nenv > 0) {
        if ((c->env = calloc(p->nenv, sizeof(*c->env))) == NULL)
            oom = true;
        for (size_t i = 0; !oom && i < p->nenv; i++) {
            char *n = strdup(p->env[i].name), *v = strdup(p->env[i].value);
            if (n == NULL || v == NULL) {
                free(n);
                free(v);
                oom = true;
                break;
            }
            c->env[i].name = n;
            c->env[i].value = v;
            c->nenv++;
        }
    }
    if (!oom && p->checksum_md5 != NULL && (c->checksum_md5 = strdup(p->checksum_md5)) == NULL)
        oom = true;
    if (!oom && p->checksum_sha1 != NULL &&
        (c->checksum_sha1 = strdup(p->checksum_sha1)) == NULL)
        oom = true;
    for (size_t i = 0; !oom && i < p->ntree; i++)
        if (tree_add(c, p->tree[i].path, p->tree[i].pid) < 0)
            oom = true;
    if (oom) {
        ks_proc_unref(c);
        return NULL;
    }
    c->parent = ks_proc_ref(p->parent);
    ks_proc_sync(c);
    return c;
}

/* ---- GetExtraInfo ----------------------------------------------------- */

/* strconv.ParseInt(s, 10, 64): 0 on syntax errors, clamped on overflow. */
static int64_t parse_int64(const char *s)
{
    bool neg = false;
    if (*s == '+' || *s == '-')
        neg = *s++ == '-';
    if (*s == '\0')
        return 0;
    uint64_t v = 0;
    bool over = false;
    for (; *s != '\0'; s++) {
        if (*s < '0' || *s > '9')
            return 0;
        if (v > (UINT64_MAX - 9) / 10)
            over = true;
        else
            v = v * 10 + (uint64_t)(*s - '0');
    }
    if (neg)
        return over || v > (uint64_t)INT64_MAX + 1 ? INT64_MIN : (int64_t)(0 - v);
    return over || v > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)v;
}

/* Reads a whole file into *dst; keeps the old value if it can't be read. */
static void read_into(const char *path, char **dst)
{
    char err[128];
    size_t len;
    char *data = ks_read_file(path, PROC_FILE_MAX, &len, err, sizeof(err));
    if (data == NULL)
        return;
    free(*dst);
    *dst = data;
}

/* netlink.TCPStatesMap */
static const char *tcp_state_name(uint8_t st)
{
    static const char *const names[] = {
        "invalid",   "established", "syn_sent",   "syn_recv", "fin_wait1", "fin_wait2",
        "time_wait", "close",       "close_wait", "last_ack", "listen",    "closing",
    };
    return st < sizeof(names) / sizeof(names[0]) ? names[st] : "";
}

/* `socket:\[([0-9]+)\]`: the inode of a socket link, -1 if not one. */
static int64_t socket_inode(const char *link, char *digits, size_t len)
{
    for (const char *s = strstr(link, "socket:["); s != NULL; s = strstr(s + 1, "socket:[")) {
        const char *d = s + 8, *e = d;
        while (*e >= '0' && *e <= '9')
            e++;
        if (e > d && *e == ']') {
            snprintf(digits, len, "%.*s", (int)(e - d), d);
            /* GetSocketInfoByInode: strconv.ParseUint(inode, 10, 32) */
            if (e - d > 10)
                return -2;
            unsigned long long v = strtoull(digits, NULL, 10);
            return v > UINT32_MAX ? -2 : (int64_t)v;
        }
    }
    return -1;
}

static void read_descriptors(struct ks_proc_extra *x, const char *dir)
{
    char fd_dir[320];
    snprintf(fd_dir, sizeof(fd_dir), "%s/fd/", dir);
    DIR *d = opendir(fd_dir);
    if (d == NULL)
        return;
    for (size_t i = 0; i < x->nfds; i++) {
        free(x->fds[i].name);
        free(x->fds[i].symlink);
    }
    free(x->fds);
    x->fds = NULL;
    x->nfds = 0;
    x->has_fds = false; /* p.Descriptors = nil */
    size_t cap = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char path[640];
        snprintf(path, sizeof(path), "%s%s", fd_dir, e->d_name);
        char *link = read_link(path);
        if (link == NULL)
            continue;
        char digits[32];
        int64_t inode = socket_inode(link, digits, sizeof(digits));
        struct ks_sock so;
        if (inode >= 0 && ks_sock_find_by_inode((uint32_t)inode, &so) == 0) {
            char src[64], dst[64], text[512];
            ks_ip_string(&so.src, src, sizeof(src));
            ks_ip_string(&so.dst, dst, sizeof(dst));
            char *host = ks_dns_host_or(&so.dst, dst);
            /* upstream prints the descriptor's name where the inode was */
            snprintf(text, sizeof(text), "socket:[%s] - %u:%s -> %s:%u, state: %s", e->d_name,
                     (unsigned)so.sport, src, host ? host : dst, (unsigned)so.dport,
                     tcp_state_name(so.state));
            free(host);
            char *t = strdup(text);
            if (t != NULL) {
                free(link);
                link = t;
            }
        }
        if (x->nfds == cap) {
            cap = cap ? cap * 2 : 16;
            struct ks_proc_fd *nf = realloc(x->fds, cap * sizeof(*nf));
            if (nf == NULL) {
                free(link);
                break;
            }
            x->fds = nf;
        }
        struct ks_proc_fd *f = &x->fds[x->nfds];
        memset(f, 0, sizeof(*f));
        f->mtime_sec = KS_GO_ZERO_TIME;
        if ((f->name = strdup(e->d_name)) == NULL) {
            free(link);
            break;
        }
        f->symlink = link;
        /* os.Lstat(link): the link's target as a path */
        struct stat st;
        if (lstat(link, &st) == 0) {
            f->size = (int64_t)st.st_size;
            f->mtime_sec = (int64_t)st.st_mtim.tv_sec;
            f->mtime_nsec = st.st_mtim.tv_nsec;
        }
        x->nfds++;
        x->has_fds = true;
    }
    closedir(d);
}

static void read_io_stats(struct ks_proc_extra *x, const char *dir)
{
    char path[320], err[128];
    size_t len;
    snprintf(path, sizeof(path), "%s/io", dir);
    char *data = ks_read_file(path, PROC_FILE_MAX, &len, err, sizeof(err));
    if (data == NULL)
        return;
    static const char *const keys[6] = {"rchar:",  "wchar:",       "syscr:",
                                        "syscw:", "read_bytes:", "write_bytes:"};
    memset(x->io, 0, sizeof(x->io)); /* p.IOStats = &procIOstats{} */
    char *save = NULL;
    for (char *line = strtok_r(data, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        /* strings.Split(line, " "): the key, then the value up to the
         * next space */
        char *sp = strchr(line, ' ');
        if (sp == NULL)
            continue;
        *sp = '\0';
        char *val = sp + 1, *end = strchr(val, ' ');
        if (end != NULL)
            *end = '\0';
        for (int i = 0; i < 6; i++)
            if (strcmp(line, keys[i]) == 0)
                x->io[i] = parse_int64(val);
    }
    free(data);
}

static void read_statm(struct ks_proc_extra *x, const char *dir)
{
    char path[320], err[128];
    size_t len;
    snprintf(path, sizeof(path), "%s/statm", dir);
    char *data = ks_read_file(path, PROC_FILE_MAX, &len, err, sizeof(err));
    if (data == NULL)
        return;
    long long v[7] = {0};
    sscanf(data, "%lld %lld %lld %lld %lld %lld %lld", &v[0], &v[1], &v[2], &v[3], &v[4],
           &v[5], &v[6]);
    free(data);
    int64_t page = (int64_t)sysconf(_SC_PAGESIZE);
    for (int i = 0; i < 6; i++)
        x->statm[i] = (int64_t)v[i] * page;
    x->statm_dt = (int64_t)v[6] * page;
}

void ks_proc_get_extra_info_at(struct ks_proc *p, const char *procfs)
{
    if (p->extra == NULL && (p->extra = calloc(1, sizeof(*p->extra))) == NULL)
        return;
    struct ks_proc_extra *x = p->extra;
    /* procfs is "/proc", or a short directory in the tests */
    char dir[256], path[320];
    snprintf(dir, sizeof(dir), "%s/%d", procfs, p->pid);

    snprintf(path, sizeof(path), "%s/environ", dir);
    ks_proc_read_env_file(p, path);
    read_descriptors(x, dir);
    read_io_stats(x, dir);
    /* readStatus */
    snprintf(path, sizeof(path), "%s/status", dir);
    read_into(path, &x->status);
    snprintf(path, sizeof(path), "%s/stat", dir);
    read_into(path, &x->stat);
    snprintf(path, sizeof(path), "%s/stack", dir);
    read_into(path, &x->stack);
    snprintf(path, sizeof(path), "%s/maps", dir);
    read_into(path, &x->maps);
    read_statm(x, dir);
}

void ks_proc_get_extra_info(struct ks_proc *p)
{
    ks_proc_get_extra_info_at(p, "/proc");
}

/* ---- json.Marshal ----------------------------------------------------- */

static int env_cmp(const void *a, const void *b)
{
    const struct ks_env_var *x = *(const struct ks_env_var *const *)a;
    const struct ks_env_var *y = *(const struct ks_env_var *const *)b;
    return strcmp(x->name, y->name);
}

static cJSON *int_object(const char *const *names, const int64_t *values, size_t n)
{
    cJSON *o = cJSON_CreateObject();
    for (size_t i = 0; o != NULL && i < n; i++)
        if (ks_json_add_int(o, names[i], values[i]) == NULL) {
            cJSON_Delete(o);
            return NULL;
        }
    return o;
}

static bool add_str(cJSON *o, const char *name, const char *v)
{
    return cJSON_AddStringToObject(o, name, v != NULL ? v : "") != NULL;
}

static const char *const statm_names[7] = {"Size", "Resident", "Shared", "Text",
                                           "Lib",  "Data",     "Dt"};
static const char *const io_names[6] = {"RChar",     "WChar",     "SyscallRead",
                                        "SyscallWrite", "ReadBytes", "WriteBytes"};

static cJSON *descriptors_json(const struct ks_proc_extra *x)
{
    if (x == NULL || !x->has_fds)
        return cJSON_CreateNull();
    cJSON *a = cJSON_CreateArray();
    for (size_t i = 0; a != NULL && i < x->nfds; i++) {
        const struct ks_proc_fd *f = &x->fds[i];
        cJSON *o = cJSON_CreateObject();
        char t[KS_GO_TIME_STRLEN];
        ks_go_time_rfc3339nano(f->mtime_sec, f->mtime_nsec, t, sizeof(t));
        if (o == NULL || !add_str(o, "ModTime", t) || !add_str(o, "Name", f->name) ||
            !add_str(o, "SymLink", f->symlink) || ks_json_add_int(o, "Size", f->size) == NULL ||
            !cJSON_AddItemToArray(a, o)) {
            cJSON_Delete(o);
            cJSON_Delete(a);
            return NULL;
        }
    }
    return a;
}

static cJSON *proc_json(const struct ks_proc *p, int depth)
{
    if (p == NULL || depth > MAX_PARENTS)
        return cJSON_CreateNull();
    cJSON *o = cJSON_CreateObject();
    if (o == NULL)
        return NULL;
    const struct ks_proc_extra *x = p->extra;
    int64_t statm[7] = {0}, io[6] = {0}, net[2] = {0};
    if (x != NULL) {
        memcpy(statm, x->statm, sizeof(x->statm));
        statm[6] = x->statm_dt;
        memcpy(io, x->io, sizeof(io));
    }
    static const char *const net_names[2] = {"ReadBytes", "WriteBytes"};
    bool ok = cJSON_AddItemToObject(o, "Statm", int_object(statm_names, statm, 7)) &&
              cJSON_AddItemToObject(o, "Parent", proc_json(p->parent, depth + 1)) &&
              cJSON_AddItemToObject(o, "IOStats", int_object(io_names, io, 6)) &&
              cJSON_AddItemToObject(o, "NetStats", int_object(net_names, net, 2));

    /* Env: a Go map, so sorted by name */
    cJSON *env = ok ? cJSON_AddObjectToObject(o, "Env") : NULL;
    ok = env != NULL;
    if (ok && p->nenv > 0) {
        const struct ks_env_var **sorted = malloc(p->nenv * sizeof(*sorted));
        ok = sorted != NULL;
        for (size_t i = 0; ok && i < p->nenv; i++)
            sorted[i] = &p->env[i];
        if (ok)
            qsort(sorted, p->nenv, sizeof(*sorted), env_cmp);
        for (size_t i = 0; ok && i < p->nenv; i++)
            ok = add_str(env, sorted[i]->name, sorted[i]->value);
        free(sorted);
    }
    cJSON *sums = ok ? cJSON_AddObjectToObject(o, "Checksums") : NULL;
    ok = sums != NULL;
    if (ok && p->checksum_md5 != NULL)
        ok = add_str(sums, KS_HASH_MD5, p->checksum_md5);
    if (ok && p->checksum_sha1 != NULL)
        ok = add_str(sums, KS_HASH_SHA1, p->checksum_sha1);

    ok = ok && add_str(o, "Status", x ? x->status : NULL) &&
         add_str(o, "Stat", x ? x->stat : NULL) && add_str(o, "Stack", x ? x->stack : NULL) &&
         add_str(o, "Maps", x ? x->maps : NULL) && add_str(o, "Comm", p->comm) &&
         add_str(o, "Path", p->path) && add_str(o, "Root", p->root) &&
         add_str(o, "RealPath", p->real_path) && add_str(o, "CWD", p->cwd);

    /* Tree: []*protocol.StringInt, whose JSON tags are "key,omitempty" and
     * "value,omitempty" */
    cJSON *tree = ok ? cJSON_AddArrayToObject(o, "Tree") : NULL;
    ok = tree != NULL;
    for (size_t i = 0; ok && i < p->ntree; i++) {
        cJSON *t = cJSON_CreateObject();
        ok = t != NULL && cJSON_AddItemToArray(tree, t);
        if (!ok) {
            cJSON_Delete(t);
            break;
        }
        if (p->tree[i].path[0] != '\0')
            ok = add_str(t, "key", p->tree[i].path);
        if (ok && p->tree[i].pid != 0)
            ok = ks_json_add_uint(t, "value", (uint32_t)p->tree[i].pid) != NULL;
    }
    ok = ok && cJSON_AddItemToObject(o, "Descriptors", descriptors_json(x));
    cJSON *args = ok ? cJSON_AddArrayToObject(o, "Args") : NULL;
    ok = args != NULL;
    for (size_t i = 0; ok && i < p->nargs; i++) {
        cJSON *a = cJSON_CreateString(p->args[i]);
        ok = a != NULL && cJSON_AddItemToArray(args, a);
        if (!ok)
            cJSON_Delete(a);
    }
    ok = ok && ks_json_add_int(o, "Starttime", p->starttime) && ks_json_add_int(o, "ID", p->pid) &&
         ks_json_add_int(o, "PPID", p->ppid) && ks_json_add_int(o, "UID", 0);
    if (!ok) {
        cJSON_Delete(o);
        return NULL;
    }
    return o;
}

cJSON *ks_proc_to_cjson(const struct ks_proc *p)
{
    return proc_json(p, 0);
}

cJSON *ks_proc_zero_cjson(void)
{
    /* Process{}: nil pointers, maps and slices are null */
    static const char *const fields[] = {"Statm", "Parent", "IOStats", "NetStats", "Env",
                                         "Checksums"};
    static const char *const strs[] = {"Status", "Stat", "Stack", "Maps", "Comm",
                                       "Path",   "Root", "RealPath", "CWD"};
    static const char *const tail[] = {"Starttime", "ID", "PPID", "UID"};
    cJSON *o = cJSON_CreateObject();
    bool ok = o != NULL;
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); i++)
        ok = cJSON_AddNullToObject(o, fields[i]) != NULL;
    for (size_t i = 0; ok && i < sizeof(strs) / sizeof(strs[0]); i++)
        ok = add_str(o, strs[i], "");
    ok = ok && cJSON_AddNullToObject(o, "Tree") && cJSON_AddNullToObject(o, "Descriptors") &&
         cJSON_AddNullToObject(o, "Args");
    for (size_t i = 0; ok && i < sizeof(tail) / sizeof(tail[0]); i++)
        ok = ks_json_add_int(o, tail[i], 0) != NULL;
    if (!ok) {
        cJSON_Delete(o);
        return NULL;
    }
    return o;
}

char *ks_proc_json(const struct ks_proc *p)
{
    cJSON *j = ks_proc_to_cjson(p);
    if (j == NULL)
        return NULL;
    char *s = ks_json_print_go(j, false);
    cJSON_Delete(j);
    return s;
}
