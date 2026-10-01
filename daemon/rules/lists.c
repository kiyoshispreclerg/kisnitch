/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/rule/operator_lists.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/rules/lists.h"

#include <dirent.h>
#include <fnmatch.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/strset.h"
#include "daemon/evloop.h"
#include "daemon/rules/regex.h"

/* Lists can be big, but not this big. */
#define LIST_FILE_MAX_SIZE (512u * 1024 * 1024)

struct file_mtime {
    char *name;
    struct timespec mtime;
};

struct ks_lists {
    enum ks_lists_kind kind;
    char *dir;
    struct ks_strset keys; /* every kind: the map keys upstream uses */
    struct ks_ipnet *nets; /* KS_LISTS_NETS */
    size_t nnets;
    struct ks_regex **res; /* KS_LISTS_REGEXP */
    size_t nres;
    /* monitor state */
    struct ks_evloop *loop;
    struct ks_timer *timer;
    struct file_mtime *mtimes;
    size_t nmtimes;
    size_t total_files;
};

/* core.Trim: strings.Trim(s, "\r\n\t "). Returns the trimmed span. */
static void trim(const char **s, size_t *n)
{
    while (*n > 0 && strchr("\r\n\t ", (*s)[0]) != NULL && (*s)[0] != '\0') {
        (*s)++;
        (*n)--;
    }
    while (*n > 0 && strchr("\r\n\t ", (*s)[*n - 1]) != NULL &&
           (*s)[*n - 1] != '\0')
        (*n)--;
}

static void clear_entries(struct ks_lists *l)
{
    ks_strset_clear(&l->keys);
    free(l->nets);
    l->nets = NULL;
    l->nnets = 0;
    for (size_t i = 0; i < l->nres; i++)
        ks_regex_free(l->res[i]);
    free(l->res);
    l->res = NULL;
    l->nres = 0;
}

/* filterDomains. Returns false to skip the line, otherwise the host span. */
static bool filter_domains(const char *line, size_t n, const char **host,
                           size_t *hlen)
{
    if (n < 9)
        return false;
    bool zeros = memcmp(line, "0.0.0.0", 7) == 0;
    bool loopback = memcmp(line, "127.0.0.1", 9) == 0;
    if (!zeros && !loopback)
        return false;
    size_t off = loopback ? 10 : 8;
    /* Upstream slices line[10:] past the end for a bare "127.0.0.1" (and
     * panics); such a line has no host anyway. */
    if (off > n)
        return false;
    *host = line + off;
    *hlen = n - off;
    static const char *const skip[] = {"local", "localhost",
                                       "localhost.localdomain", "broadcasthost"};
    for (size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++)
        if (strlen(skip[i]) == *hlen && memcmp(skip[i], *host, *hlen) == 0)
            return false;
    return true;
}

/* Adds the entries of one file. Returns the number of duplicates. */
static size_t read_list(struct ks_lists *l, const char *raw, size_t len,
                        const char *file)
{
    size_t dups = 0;
    const char *p = raw, *end = raw + len;

    while (p <= end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);
        const char *line = p;
        p = nl != NULL ? nl + 1 : end + 1;

        if (l->kind == KS_LISTS_DOMAINS) {
            const char *host;
            size_t hlen;
            if (!filter_domains(line, n, &host, &hlen))
                continue;
            trim(&host, &hlen);
            int r = ks_strset_add(&l->keys, host, hlen);
            if (r == 0)
                dups++;
            continue;
        }

        if (n == 0 || line[0] == '#')
            continue;
        const char *key = line;
        size_t klen = n;
        trim(&key, &klen);
        if (ks_strset_has(&l->keys, key, klen)) {
            dups++;
            continue;
        }

        if (l->kind == KS_LISTS_NETS) {
            char cidr[128];
            struct ks_ipnet net;
            char err[200];
            /* Longer lines can't be valid CIDRs. */
            snprintf(cidr, sizeof(cidr), "%.*s", (int)(klen < 127 ? klen : 127), key);
            if (klen >= sizeof(cidr) || memchr(key, '\0', klen) != NULL ||
                ks_parse_cidr(cidr, &net, err, sizeof(err)) < 0) {
                ks_warning("Error parsing net from list: %s, (%s)",
                           klen >= sizeof(cidr) ? "line too long" : err, file);
                continue;
            }
            struct ks_ipnet *nets = realloc(l->nets, (l->nnets + 1) * sizeof(*nets));
            if (nets == NULL || ks_strset_add(&l->keys, key, klen) < 0) {
                if (nets != NULL)
                    l->nets = nets;
                ks_error("out of memory loading list %s", file);
                return dups;
            }
            l->nets = nets;
            l->nets[l->nnets++] = net;
        } else if (l->kind == KS_LISTS_REGEXP) {
            /* Upstream checks the trimmed line for duplicates but compiles
             * and stores the line as is. */
            char *pattern = strndup(line, n);
            char err[256];
            if (pattern == NULL)
                return dups;
            struct ks_regex *re = ks_regex_compile(pattern, err, sizeof(err));
            free(pattern);
            if (re == NULL) {
                ks_warning("Error compiling regexp from list: %s, (%s)", err, file);
                continue;
            }
            int added = ks_strset_add(&l->keys, line, n);
            if (added <= 0) {
                ks_regex_free(re);
                if (added < 0)
                    return dups;
                continue;
            }
            struct ks_regex **res = realloc(l->res, (l->nres + 1) * sizeof(*res));
            if (res == NULL) {
                ks_regex_free(re);
                return dups;
            }
            l->res = res;
            l->res[l->nres++] = re;
        } else {
            if (ks_strset_add(&l->keys, key, klen) < 0)
                return dups;
        }
    }
    return dups;
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* filepath.Glob(filepath.Join(dir, "*.*")): sorted names, hidden files
 * included (the callers skip them). */
static char **glob_dir(const char *dir, size_t *count)
{
    *count = 0;
    DIR *d = opendir(dir);
    if (d == NULL)
        return NULL;
    char **names = NULL;
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (fnmatch("*.*", e->d_name, 0) != 0 || strcmp(e->d_name, ".") == 0 ||
            strcmp(e->d_name, "..") == 0)
            continue;
        char **nn = realloc(names, (n + 1) * sizeof(*nn));
        if (nn == NULL)
            break;
        names = nn;
        if ((names[n] = strdup(e->d_name)) == NULL)
            break;
        n++;
    }
    closedir(d);
    if (n > 0)
        qsort(names, n, sizeof(*names), cmp_names);
    *count = n;
    return names;
}

static void free_names(char **names, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(names[i]);
    free(names);
}

static char *join(const char *dir, const char *name)
{
    size_t n = strlen(dir) + strlen(name) + 2;
    char *p = malloc(n);
    if (p != NULL)
        snprintf(p, n, "%s/%s", dir, name);
    return p;
}

/* readLists */
static void read_lists(struct ks_lists *l)
{
    clear_entries(l);

    size_t nfiles, dups = 0;
    char **names = glob_dir(l->dir, &nfiles);
    for (size_t i = 0; i < nfiles; i++) {
        if (names[i][0] == '.')
            continue;
        char *path = join(l->dir, names[i]);
        char err[512];
        size_t len;
        char *raw = path ? ks_read_file(path, LIST_FILE_MAX_SIZE, &len, err,
                                        sizeof(err)) : NULL;
        if (raw == NULL) {
            ks_warning("Error reading list of IPs (%s): %s",
                       path ? path : names[i], path ? err : "out of memory");
            free(path);
            continue;
        }
        size_t before = l->keys.count;
        dups += read_list(l, raw, len, path);
        ks_info("%zu entries loaded (%zu new), %s", l->keys.count,
                l->keys.count - before, path);
        free(raw);
        free(path);
    }
    ks_info("%zu lists loaded, %zu entries, %zu duplicated", nfiles,
            l->keys.count, dups);
    free_names(names, nfiles);
}

static struct timespec *find_mtime(struct ks_lists *l, const char *name)
{
    for (size_t i = 0; i < l->nmtimes; i++)
        if (strcmp(l->mtimes[i].name, name) == 0)
            return &l->mtimes[i].mtime;
    return NULL;
}

static void forget_mtimes(struct ks_lists *l)
{
    for (size_t i = 0; i < l->nmtimes; i++)
        free(l->mtimes[i].name);
    free(l->mtimes);
    l->mtimes = NULL;
    l->nmtimes = 0;
}

/* One iteration of monitorLists. */
void ks_lists_poll(struct ks_lists *l)
{
    bool need_reload = false;
    size_t nfiles, counted = 0;
    char **names = glob_dir(l->dir, &nfiles);

    struct file_mtime *fresh = calloc(nfiles ? nfiles : 1, sizeof(*fresh));
    size_t nfresh = 0;
    for (size_t i = 0; i < nfiles && fresh != NULL; i++) {
        if (names[i][0] == '.')
            continue;
        char *path = join(l->dir, names[i]);
        struct stat st;
        if (path != NULL && stat(path, &st) == 0 && !S_ISDIR(st.st_mode)) {
            struct timespec *old = find_mtime(l, names[i]);
            if (old != NULL && (old->tv_sec != st.st_mtim.tv_sec ||
                                old->tv_nsec != st.st_mtim.tv_nsec))
                need_reload = true;
            fresh[nfresh].name = names[i];
            fresh[nfresh].mtime = st.st_mtim;
            names[i] = NULL;
            nfresh++;
        }
        free(path);
        counted++;
    }
    free_names(names, nfiles);

    forget_mtimes(l);
    l->mtimes = fresh;
    l->nmtimes = nfresh;

    if (counted != l->total_files)
        need_reload = true;
    l->total_files = counted;

    if (need_reload)
        read_lists(l);
}

static void on_timer(void *data)
{
    ks_lists_poll(data);
}

struct ks_lists *ks_lists_new(enum ks_lists_kind kind, const char *dir,
                              struct ks_evloop *loop)
{
    struct ks_lists *l = calloc(1, sizeof(*l));
    if (l == NULL || (l->dir = strdup(dir)) == NULL) {
        free(l);
        return NULL;
    }
    l->kind = kind;
    ks_strset_init(&l->keys);
    ks_info("monitor lists started: %s", dir);
    ks_lists_poll(l);
    if (loop != NULL) {
        l->loop = loop;
        l->timer = ks_evloop_add_timer(loop, KS_LISTS_POLL_INTERVAL_NS,
                                       KS_LISTS_POLL_INTERVAL_NS, on_timer, l);
    }
    return l;
}

void ks_lists_free(struct ks_lists *l)
{
    if (l == NULL)
        return;
    if (l->timer != NULL)
        ks_evloop_cancel_timer(l->loop, l->timer);
    ks_info("lists monitor stopped: %s", l->dir);
    clear_entries(l);
    forget_mtimes(l);
    free(l->dir);
    free(l);
}

bool ks_lists_has(const struct ks_lists *l, const char *s)
{
    return ks_strset_has(&l->keys, s, strlen(s));
}

bool ks_lists_match_regexp(struct ks_lists *l, const char *s)
{
    for (size_t i = 0; i < l->nres; i++)
        if (ks_regex_match(l->res[i], s))
            return true;
    return false;
}

bool ks_lists_match_net(const struct ks_lists *l, const struct ks_ip *ip)
{
    for (size_t i = 0; i < l->nnets; i++)
        if (ks_ipnet_contains(&l->nets[i], ip))
            return true;
    return false;
}

size_t ks_lists_count(const struct ks_lists *l)
{
    return l->keys.count;
}
