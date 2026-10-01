/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/rule/loader.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/rules/loader.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/duration.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/evloop.h"

#define RULE_FILE_MAX_SIZE (16u * 1024 * 1024)

struct temp_timer {
    struct ks_loader *l;
    char *name;
    char *duration;
    struct ks_timer *timer;
    struct temp_timer *next;
};

struct ks_loader {
    struct ks_rules_env env;
    bool live_reload;
    bool live_running;
    int ifd; /* inotify */
    int wd;
    char *path;
    struct ks_rule **rules; /* sorted by name */
    size_t n, cap;
    bool checksums;
    struct temp_timer *timers;
};

/* ---- the rule map ----------------------------------------------------- */

/* Binary search; returns the index of `name` or where it would go. */
static size_t find_index(const struct ks_loader *l, const char *name, bool *found)
{
    size_t lo = 0, hi = l->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(l->rules[mid]->name, name);
        if (c == 0) {
            *found = true;
            return mid;
        }
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = false;
    return lo;
}

static struct ks_rule *find(const struct ks_loader *l, const char *name)
{
    bool found;
    size_t i = find_index(l, name, &found);
    return found ? l->rules[i] : NULL;
}

/* l.rules[name] = r, freeing the rule it replaces. */
static int store(struct ks_loader *l, struct ks_rule *r)
{
    bool found;
    size_t i = find_index(l, r->name, &found);
    if (found) {
        if (l->rules[i] != r)
            ks_rule_free(l->rules[i]);
        l->rules[i] = r;
        return 0;
    }
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 16;
        struct ks_rule **nr = realloc(l->rules, cap * sizeof(*nr));
        if (nr == NULL)
            return -1;
        l->rules = nr;
        l->cap = cap;
    }
    memmove(l->rules + i + 1, l->rules + i, (l->n - i) * sizeof(*l->rules));
    l->rules[i] = r;
    l->n++;
    return 0;
}

/* delete(l.rules, name), returning the rule (not freed). */
static struct ks_rule *unstore(struct ks_loader *l, const char *name)
{
    bool found;
    size_t i = find_index(l, name, &found);
    if (!found)
        return NULL;
    struct ks_rule *r = l->rules[i];
    memmove(l->rules + i, l->rules + i + 1, (l->n - i - 1) * sizeof(*l->rules));
    l->n--;
    return r;
}

size_t ks_loader_num_rules(const struct ks_loader *l)
{
    return l->n;
}

const struct ks_rule *ks_loader_rule_at(const struct ks_loader *l, size_t i)
{
    return i < l->n ? l->rules[i] : NULL;
}

const struct ks_rule *ks_loader_get(const struct ks_loader *l, const char *name)
{
    return find(l, name);
}

const char *ks_loader_path(const struct ks_loader *l)
{
    return l->path ? l->path : "";
}

void ks_loader_enable_checksums(struct ks_loader *l, bool enable)
{
    ks_debug("[rules loader] EnableChecksums: %d", enable);
    l->checksums = enable;
}

/* ---- helpers ---------------------------------------------------------- */

static bool is_temporary(const struct ks_rule *r)
{
    return ks_rule_duration_kind(r->duration) == KS_RULE_TEMPORARY;
}

static bool is_always(const struct ks_rule *r)
{
    return strcmp(r->duration, KS_DURATION_ALWAYS) == 0;
}

/* cleanListsRule: stops the lists of a "lists" operator, or of the first
 * "lists" operator of a "list" rule (upstream stops at the first one). */
static void clean_lists(struct ks_rule *r)
{
    struct ks_operator *o = &r->operator;
    if (strcmp(o->type, KS_TYPE_LISTS) == 0) {
        ks_operator_reset(o);
    } else if (strcmp(o->type, KS_TYPE_LIST) == 0) {
        for (size_t i = 0; i < o->list.len; i++) {
            struct ks_operator *item = KS_ARRAY_ITEM(o->list, struct ks_operator, i);
            if (item->type != NULL && strcmp(item->type, KS_TYPE_LISTS) == 0) {
                ks_operator_reset(item);
                break;
            }
        }
    }
}

/* fmt.Sprint(l.Path, "/", name, ".json"). Rule names come from the UI over
 * the network; refuse the ones that would escape the directory. */
static char *rule_file(const struct ks_loader *l, const char *name, char *err,
                       size_t errlen)
{
    if (strchr(name, '/') != NULL) {
        snprintf(err, errlen, "invalid rule name (contains '/'): %s", name);
        return NULL;
    }
    size_t n = strlen(ks_loader_path(l)) + strlen(name) + 7;
    char *p = malloc(n);
    if (p == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    snprintf(p, n, "%s/%s.json", ks_loader_path(l), name);
    return p;
}

static int delete_rule_from_disk(struct ks_loader *l, const char *name,
                                 char *err, size_t errlen)
{
    char *path = rule_file(l, name, err, errlen);
    if (path == NULL)
        return -1;
    int ret = 0;
    if (unlink(path) < 0) {
        snprintf(err, errlen, "remove %s: %s", path, strerror(errno));
        ret = -1;
    }
    free(path);
    return ret;
}

/* deleteOldRuleFromDisk: an "always" rule turned temporary leaves the disk. */
static void delete_old_rule_from_disk(struct ks_loader *l,
                                      const struct ks_rule *old,
                                      const struct ks_rule *new_rule)
{
    char err[512];
    if (is_always(old) && !is_always(new_rule) &&
        delete_rule_from_disk(l, old->name, err, sizeof(err)) < 0)
        ks_error("Error deleting old rule from disk: %s", old->name);
}

/* unmarshalOperatorList (deprecated format): a list rule whose operators are
 * a JSON string in "data". */
static int unmarshal_operator_list(struct ks_operator *o, char *err,
                                   size_t errlen)
{
    if (strcmp(o->type, KS_TYPE_LIST) != 0 || o->list.len != 0 ||
        o->data[0] == '\0')
        return 0;
    struct ks_array list;
    char e[256];
    if (ks_operator_list_parse(o->data, &list, e, sizeof(e)) < 0) {
        snprintf(err, errlen, "error loading rule of type list: %s", e);
        return -1;
    }
    for (size_t i = 0; i < o->list.len; i++)
        ks_operator_reset(KS_ARRAY_ITEM(o->list, struct ks_operator, i));
    free(o->list.items); /* empty, but may be a non-nil [] */
    o->list = list;
    free(o->data);
    o->data = strdup("");
    if (o->data == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    return 0;
}

/* Compiles the operator and, for list rules, its items (one level).
 * `from_disk` picks upstream's message: loadRule says "(1) Error compiling",
 * replaceUserRule "(2) error compiling". */
static int compile_rule(struct ks_loader *l, struct ks_rule *r, bool from_disk,
                        char *err, size_t errlen)
{
    const char *tag = from_disk ? "(1) Error" : "(2) error";
    char e[512];
    if (ks_operator_compile(&r->operator, &l->env, e, sizeof(e)) < 0) {
        ks_warning("Operator.Compile() error: %s, %s (%s)", e, r->operator.data,
                   r->name);
        snprintf(err, errlen, "%s compiling rule: %s", tag, e);
        return -1;
    }
    if (strcmp(r->operator.type, KS_TYPE_LIST) == 0) {
        for (size_t i = 0; i < r->operator.list.len; i++) {
            struct ks_operator *item =
                KS_ARRAY_ITEM(r->operator.list, struct ks_operator, i);
            if (ks_operator_compile(item, &l->env, e, sizeof(e)) < 0) {
                ks_warning("Operator.Compile() error: %s (%s)", e, r->name);
                snprintf(err, errlen, "%s compiling list rule: %s", tag, e);
                return -1;
            }
        }
    }
    return 0;
}

/* ---- temporary rules -------------------------------------------------- */

static void free_temp(struct temp_timer *t)
{
    free(t->name);
    free(t->duration);
    free(t);
}

static void on_temp_expired(void *data)
{
    struct temp_timer *t = data;
    struct ks_loader *l = t->l;

    /* The timer is gone once this returns. */
    for (struct temp_timer **pp = &l->timers; *pp != NULL; pp = &(*pp)->next)
        if (*pp == t) {
            *pp = t->next;
            break;
        }

    ks_info("Temporary rule expired: %s - %s", t->name, t->duration);
    struct ks_rule *r = find(l, t->name);
    if (r != NULL) {
        if (strcmp(r->duration, t->duration) != 0) {
            ks_debug("%s temporary rule expired, but has new Duration, old: %s, new: %s",
                     t->name, t->duration, r->duration);
        } else {
            ks_rule_free(unstore(l, t->name));
        }
    }
    free_temp(t);
}

/* scheduleTemporaryRule. Like time.AfterFunc, timers are never cancelled. */
static int schedule_temporary(struct ks_loader *l, const struct ks_rule *r,
                              char *err, size_t errlen)
{
    int64_t ns;
    if (ks_parse_duration(r->duration, &ns, err, errlen) < 0)
        return -1;
    if (l->env.loop == NULL) {
        ks_warning("no event loop: temporary rule %s won't expire", r->name);
        return 0;
    }
    struct temp_timer *t = calloc(1, sizeof(*t));
    if (t == NULL || (t->name = strdup(r->name)) == NULL ||
        (t->duration = strdup(r->duration)) == NULL)
        goto oom;
    t->l = l;
    t->timer = ks_evloop_add_timer(l->env.loop, ns, 0, on_temp_expired, t);
    if (t->timer == NULL)
        goto oom;
    t->next = l->timers;
    l->timers = t;
    return 0;
oom:
    if (t != NULL)
        free_temp(t);
    snprintf(err, errlen, "out of memory");
    return -1;
}

/* ---- loading ---------------------------------------------------------- */

int ks_loader_load_rule(struct ks_loader *l, const char *file, char *err,
                        size_t errlen)
{
    char e[512];
    size_t len;
    char *raw = ks_read_file(file, RULE_FILE_MAX_SIZE, &len, e, sizeof(e));
    if (raw == NULL) {
        snprintf(err, errlen, "Error while reading %s: %s", file, e);
        return -1;
    }
    struct ks_rule *r = ks_rule_parse(raw, len, e, sizeof(e));
    free(raw);
    if (r == NULL) {
        snprintf(err, errlen, "Error parsing rule from %s: %s", file, e);
        return -1;
    }

    struct ks_rule *old = find(l, r->name);
    if (old != NULL)
        clean_lists(old);

    if (!r->enabled) {
        /* Disabled rules are only parsed, not compiled. */
        if (unmarshal_operator_list(&r->operator, err, errlen) < 0) {
            ks_rule_free(r);
            return -1;
        }
    } else if (compile_rule(l, r, true, err, errlen) < 0) {
        ks_rule_free(r);
        return -1;
    }
    if (old != NULL)
        delete_old_rule_from_disk(l, old, r);

    char desc[512];
    ks_rule_describe(r, desc, sizeof(desc));
    ks_debug("Loaded rule from %s: %s", file, desc);
    if (store(l, r) < 0) {
        ks_rule_free(r);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (r->enabled && is_temporary(r)) {
        /* Upstream ignores this error here. */
        schedule_temporary(l, r, e, sizeof(e));
    }
    return 0;
}

/* core.ExpandPath: "~" -> home directory, then filepath.Abs. */
static char *expand_path(const char *path, char *err, size_t errlen)
{
    char buf[PATH_MAX * 2];
    if (path[0] == '~') {
        struct passwd pw, *res = NULL;
        char pwbuf[4096];
        if (getpwuid_r(getuid(), &pw, pwbuf, sizeof(pwbuf), &res) != 0 || res == NULL) {
            snprintf(err, errlen, "user: unknown userid %u", (unsigned)getuid());
            return NULL;
        }
        snprintf(buf, sizeof(buf), "%s%s", pw.pw_dir, path + 1);
    } else {
        snprintf(buf, sizeof(buf), "%s", path);
    }

    char abs[PATH_MAX * 3];
    if (buf[0] == '/') {
        snprintf(abs, sizeof(abs), "%s", buf);
    } else {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            snprintf(err, errlen, "getwd: %s", strerror(errno));
            return NULL;
        }
        snprintf(abs, sizeof(abs), "%s/%s", cwd, buf);
    }

    /* filepath.Clean, on an absolute path. */
    char *out = malloc(strlen(abs) + 2);
    if (out == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    size_t o = 0;
    const char *p = abs;
    while (*p != '\0') {
        while (*p == '/')
            p++;
        const char *e = p;
        while (*e != '\0' && *e != '/')
            e++;
        size_t n = (size_t)(e - p);
        if (n == 0 || (n == 1 && p[0] == '.')) {
            /* skip */
        } else if (n == 2 && p[0] == '.' && p[1] == '.') {
            while (o > 0 && out[o - 1] != '/')
                o--;
            if (o > 0)
                o--;
        } else {
            out[o++] = '/';
            memcpy(out + o, p, n);
            o += n;
        }
        p = e;
    }
    if (o == 0)
        out[o++] = '/';
    out[o] = '\0';
    return out;
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static void on_inotify(int fd, uint32_t events, void *data);

static void start_live_reload(struct ks_loader *l)
{
    ks_debug("Rules watcher started on path %s ...", l->path);
    l->wd = inotify_add_watch(l->ifd, l->path,
                              IN_MODIFY | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF);
    if (l->wd < 0) {
        ks_error("Could not watch path: %s", strerror(errno));
        return;
    }
    l->live_running = true;
}

static void stop_live_reload(struct ks_loader *l)
{
    if (!l->live_running)
        return;
    inotify_rm_watch(l->ifd, l->wd);
    l->wd = -1;
    l->live_running = false;
    ks_debug("[rules] liveReloadWorker() exited");
}

int ks_loader_load(struct ks_loader *l, const char *path, char *err,
                   size_t errlen)
{
    struct stat st;
    ks_debug("rules.Loader.Load(): %s", path);
    if (stat(path, &st) < 0 && errno == ENOENT) {
        snprintf(err, errlen,
                 "Path '%s' does not exist\nCreate it if you want to save rules to disk",
                 path);
        return -1;
    }
    char e[512];
    char *abs = expand_path(path, e, sizeof(e));
    if (abs == NULL) {
        snprintf(err, errlen,
                 "Error accessing rules path: %s.\nCreate it if you want to save rules to disk",
                 e);
        return -1;
    }

    /* filepath.Glob(filepath.Join(path, "*.json")), sorted. */
    char **names = NULL;
    size_t nnames = 0;
    DIR *d = opendir(abs);
    if (d != NULL) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (fnmatch("*.json", de->d_name, 0) != 0)
                continue;
            char **nn = realloc(names, (nnames + 1) * sizeof(*nn));
            if (nn == NULL)
                break;
            names = nn;
            if ((names[nnames] = strdup(de->d_name)) == NULL)
                break;
            nnames++;
        }
        closedir(d);
    }
    if (nnames > 0)
        qsort(names, nnames, sizeof(*names), cmp_names);

    free(l->path);
    l->path = abs;

    for (size_t i = 0; i < nnames; i++) {
        size_t n = strlen(abs) + strlen(names[i]) + 2;
        char *file = malloc(n);
        if (file != NULL) {
            snprintf(file, n, "%s/%s", abs, names[i]);
            ks_debug("Reading rule from %s", file);
            if (ks_loader_load_rule(l, file, e, sizeof(e)) < 0)
                ks_warning("%s", e);
            free(file);
        }
        free(names[i]);
    }
    free(names);

    if (l->live_reload && !l->live_running && l->ifd >= 0)
        start_live_reload(l);
    return 0;
}

static void clear_rules(struct ks_loader *l)
{
    for (size_t i = 0; i < l->n; i++)
        ks_rule_free(l->rules[i]);
    l->n = 0;
}

int ks_loader_reload(struct ks_loader *l, const char *path, char *err,
                     size_t errlen)
{
    struct stat st;
    if (path == NULL || path[0] == '\0')
        path = KS_RULES_DEFAULT_PATH;
    ks_info("rules.Loader.Reload(): %s", path);
    if (stat(path, &st) < 0 && errno == ENOENT) {
        snprintf(err, errlen, "The new path '%s' does not exist", path);
        return -1;
    }
    stop_live_reload(l);
    for (size_t i = 0; i < l->n; i++)
        clean_lists(l->rules[i]);
    clear_rules(l);
    return ks_loader_load(l, path, err, errlen);
}

/* deleteRule: a rule file was removed from disk. */
static void delete_rule_file(struct ks_loader *l, const char *file)
{
    const char *base = strrchr(file, '/');
    base = base ? base + 1 : file;
    size_t n = strlen(base);
    if (n < 5)
        return;
    char *name = strndup(base, n - 5);
    if (name == NULL)
        return;
    struct ks_rule *r = find(l, name);
    char err[512];
    if (r != NULL && is_always(r) && ks_loader_delete(l, name, err, sizeof(err)) < 0)
        ks_debug("%s", err);
    free(name);
}

static bool has_json_suffix(const char *s)
{
    size_t n = strlen(s);
    return n >= 5 && strcmp(s + n - 5, ".json") == 0;
}

static void on_inotify(int fd, uint32_t events, void *data)
{
    struct ks_loader *l = data;
    union {
        struct inotify_event ev; /* for alignment */
        char buf[4096];
    } u;
    char *buf = u.buf;
    (void)events;

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(u.buf));
        if (n <= 0)
            return;
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            p += sizeof(*ev) + ev->len;

            if (ev->mask & IN_Q_OVERFLOW) {
                ks_error("File system watcher error: fsnotify queue overflow");
                continue;
            }
            if (!l->live_running || ev->wd != l->wd)
                continue;
            /* fsnotify's event name: the watched path plus the file name. */
            char file[PATH_MAX * 2];
            if (ev->len > 0)
                snprintf(file, sizeof(file), "%s/%s", l->path, ev->name);
            else
                snprintf(file, sizeof(file), "%s", l->path);

            if (ev->mask & IN_MODIFY) { /* fsnotify.Write */
                if (has_json_suffix(file)) {
                    const char *base = strrchr(file, '/');
                    char err[1024];
                    ks_important("Ruleset changed due to %s, reloading ...",
                                 base ? base + 1 : file);
                    if (ks_loader_load_rule(l, file, err, sizeof(err)) < 0)
                        ks_warning("%s", err);
                }
            } else if (ev->mask & (IN_DELETE | IN_DELETE_SELF)) { /* Remove */
                if (has_json_suffix(file)) {
                    const char *base = strrchr(file, '/');
                    ks_important("Rule deleted %s", base ? base + 1 : file);
                    delete_rule_file(l, file);
                }
            }
            if (ev->mask & IN_IGNORED)
                l->live_running = false; /* the directory went away */
        }
    }
}

/* ---- user rules ------------------------------------------------------- */

/* replaceUserRule. *stored tells whether `r` is now owned by the map. */
static int replace_user_rule(struct ks_loader *l, struct ks_rule *r,
                             bool *stored, char *err, size_t errlen)
{
    char e[512];
    *stored = false;

    struct ks_rule *old = find(l, r->name);
    if (old != NULL) {
        delete_old_rule_from_disk(l, old, r);
        clean_lists(old);
    }
    if (unmarshal_operator_list(&r->operator, e, sizeof(e)) < 0)
        ks_error("%s", e);

    if (r->enabled && compile_rule(l, r, false, err, errlen) < 0)
        return -1;

    if (store(l, r) < 0) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    *stored = true;
    if (r->enabled && is_temporary(r))
        return schedule_temporary(l, r, err, errlen);
    return 0;
}

int ks_loader_save(struct ks_loader *l, struct ks_rule *r, const char *path,
                   char *err, size_t errlen)
{
    (void)l;
    char now[64];
    ks_rfc3339_now(now, sizeof(now));
    char *updated = strdup(now);
    if (updated == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    free(r->updated);
    r->updated = updated;

    char desc[512], e[512];
    ks_rule_describe(r, desc, sizeof(desc));
    char *json = ks_rule_to_json(r);
    if (json == NULL) {
        snprintf(err, errlen, "Error while saving rule %s to %s: out of memory",
                 desc, path);
        return -1;
    }
    int ret = ks_write_file(path, json, strlen(json), 0600, e, sizeof(e));
    free(json);
    if (ret < 0)
        snprintf(err, errlen, "Error while saving rule %s to %s: %s", desc, path, e);
    return ret;
}

static int save_to_rules_dir(struct ks_loader *l, struct ks_rule *r, char *err,
                             size_t errlen)
{
    char *file = rule_file(l, r->name, err, errlen);
    if (file == NULL)
        return -1;
    int ret = ks_loader_save(l, r, file, err, errlen);
    free(file);
    return ret;
}

int ks_loader_add(struct ks_loader *l, struct ks_rule *r, bool save,
                  char *err, size_t errlen)
{
    bool stored = false;

    /* addUserRule: "once" rules aren't kept. */
    if (ks_rule_duration_kind(r->duration) != KS_RULE_ONCE) {
        /* setUniqueName */
        if (find(l, r->name) != NULL) {
            size_t blen = strlen(r->name);
            char *base = strdup(r->name);
            char *name = malloc(blen + 24);
            if (base == NULL || name == NULL) {
                free(base);
                free(name);
                ks_rule_free(r);
                snprintf(err, errlen, "out of memory");
                return -1;
            }
            for (int idx = 2;; idx++) {
                snprintf(name, blen + 24, "%s-%d", base, idx);
                if (find(l, name) == NULL)
                    break;
            }
            free(base);
            free(r->name);
            r->name = name;
        }
        /* Upstream ignores errors here: a rule that fails to compile is
         * not added, but is still saved below. */
        char e[512];
        replace_user_rule(l, r, &stored, e, sizeof(e));
    }

    int ret = 0;
    if (save)
        ret = save_to_rules_dir(l, r, err, errlen);
    if (!stored)
        ks_rule_free(r);
    return ret;
}

int ks_loader_replace(struct ks_loader *l, struct ks_rule *r, bool save,
                      char *err, size_t errlen)
{
    bool stored;
    if (replace_user_rule(l, r, &stored, err, errlen) < 0) {
        if (!stored)
            ks_rule_free(r);
        return -1;
    }
    if (save)
        return save_to_rules_dir(l, r, err, errlen);
    return 0;
}

int ks_loader_delete(struct ks_loader *l, const char *name, char *err,
                     size_t errlen)
{
    struct ks_rule *r = find(l, name);
    if (r == NULL)
        return 0;
    clean_lists(r);
    unstore(l, name);

    int ret = 0;
    if (is_always(r)) {
        char desc[512];
        ks_rule_describe(r, desc, sizeof(desc));
        ks_info("Delete() rule: %s", desc);
        ret = delete_rule_from_disk(l, r->name, err, errlen);
    }
    ks_rule_free(r);
    return ret;
}

/* ---- matching --------------------------------------------------------- */

const struct ks_rule *ks_loader_find_first_match(struct ks_loader *l,
                                                 const struct ks_conn *c)
{
    const struct ks_rule *match = NULL;
    for (size_t i = 0; i < l->n; i++) {
        const struct ks_rule *r = l->rules[i];
        if (!r->enabled) /* not in activeRules */
            continue;
        if (!ks_operator_match(&r->operator, c, l->checksums))
            continue;
        /* Keep going until a deny/reject or a precedence rule. */
        match = r;
        if (strcmp(r->action, KS_ACTION_REJECT) == 0 ||
            strcmp(r->action, KS_ACTION_DENY) == 0 || r->precedence)
            return r;
    }
    return match;
}

/* ---- lifecycle -------------------------------------------------------- */

struct ks_loader *ks_loader_new(struct ks_evloop *loop,
                                const struct ks_aliases *aliases,
                                bool live_reload)
{
    struct ks_loader *l = calloc(1, sizeof(*l));
    if (l == NULL)
        return NULL;
    l->env.loop = loop;
    l->env.aliases = aliases;
    l->live_reload = live_reload && loop != NULL;
    l->ifd = -1;
    l->wd = -1;
    if (l->live_reload) {
        l->ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (l->ifd < 0 || ks_evloop_add_fd(loop, l->ifd, EPOLLIN, on_inotify, l) < 0) {
            ks_error("Could not start the rules watcher: %s", strerror(errno));
            if (l->ifd >= 0)
                close(l->ifd);
            l->ifd = -1;
        }
    }
    return l;
}

void ks_loader_free(struct ks_loader *l)
{
    if (l == NULL)
        return;
    if (l->ifd >= 0) {
        ks_evloop_del_fd(l->env.loop, l->ifd);
        close(l->ifd);
    }
    while (l->timers != NULL) {
        struct temp_timer *t = l->timers;
        l->timers = t->next;
        ks_evloop_cancel_timer(l->env.loop, t->timer);
        free_temp(t);
    }
    clear_rules(l);
    free(l->rules);
    free(l->path);
    free(l);
}
