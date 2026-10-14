/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/desktop_parser.py, with the parts of
 * Python's configparser it relies on (ConfigParser(strict=False), raw
 * values).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#define _XOPEN_SOURCE 700 /* realpath() */
#include "ui/desktop.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/unicode.h"
#include "ui/pyjson.h"

#define DESKTOP_MAX_SIZE (1024 * 1024)

struct app {
    int refs;
    char *name, *icon, *desc, *path;
};

static void app_unref(void *v)
{
    struct app *a = v;
    if (a == NULL || --a->refs > 0)
        return;
    free(a->name);
    free(a->icon);
    free(a->desc);
    free(a->path);
    free(a);
}

/* self.fixes */
static const char *const fixes[][2] = {
    {"/opt/google/chrome/chrome", "/opt/google/chrome/google-chrome"},
    {"/usr/lib/firefox/firefox", "/usr/lib/firefox/firefox.sh"},
    {"/usr/bin/pidgin.orig", "/usr/bin/pidgin"},
};

/* ---- configparser ------------------------------------------------------ */

struct ini_opt {
    char *section, *key; /* key lowercased (optionxform) */
    struct ks_pybuf val;
};

struct ini {
    struct ini_opt *v;
    size_t len, cap;
};

static void ini_free(struct ini *ini)
{
    for (size_t i = 0; i < ini->len; i++) {
        free(ini->v[i].section);
        free(ini->v[i].key);
        free(ini->v[i].val.s);
    }
    free(ini->v);
}

static const char *ini_get(const struct ini *ini, const char *section, const char *key)
{
    for (size_t i = 0; i < ini->len; i++) {
        if (strcmp(ini->v[i].section, section) == 0 && strcasecmp(ini->v[i].key, key) == 0)
            return ini->v[i].val.s ? ini->v[i].val.s : "";
    }
    return NULL;
}

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v';
}

/* RawConfigParser._read(): false on any error (MissingSectionHeaderError,
 * ParsingError), which makes upstream skip the file. */
static bool ini_parse(struct ini *ini, const char *text, size_t n)
{
    char *section = NULL;
    struct ini_opt *cur = NULL;
    size_t indent_level = 0;
    bool ok = true;
    for (size_t i = 0; i < n && ok;) {
        const char *nl = memchr(text + i, '\n', n - i);
        size_t ll = nl ? (size_t)(nl - (text + i)) : n - i;
        const char *line = text + i;
        i += ll + 1;
        /* strip */
        size_t s = 0, e = ll;
        while (s < e && is_space(line[s]))
            s++;
        while (e > s && is_space(line[e - 1]))
            e--;
        if (s < e && (line[s] == '#' || line[s] == ';'))
            continue; /* comment */
        if (s == e) {
            /* empty_lines_in_values: kept inside a value */
            if (cur != NULL)
                ks_pybuf_add(&cur->val, "\n", 1);
            continue;
        }
        size_t indent = s;
        if (cur != NULL && indent > indent_level) {
            ks_pybuf_add(&cur->val, "\n", 1);
            ks_pybuf_add(&cur->val, line + s, e - s);
            continue;
        }
        indent_level = indent;
        if (line[s] == '[') {
            /* \[(?P<header>.+)\] */
            const char *close = NULL;
            for (size_t k = e; k > s + 1; k--) {
                if (line[k - 1] == ']') {
                    close = line + k - 1;
                    break;
                }
            }
            if (close != NULL && close > line + s + 1) {
                free(section);
                section = strndup(line + s + 1, (size_t)(close - (line + s + 1)));
                cur = NULL;
                if (section == NULL)
                    ok = false;
                continue;
            }
        }
        if (section == NULL) {
            ok = false; /* MissingSectionHeaderError */
            break;
        }
        /* (?P<option>.*?)\s*(?P<vi>=|:)\s*(?P<value>.*)$ */
        size_t d = s;
        while (d < e && line[d] != '=' && line[d] != ':')
            d++;
        if (d == e) {
            ok = false; /* ParsingError */
            break;
        }
        size_t ke = d;
        while (ke > s && is_space(line[ke - 1]))
            ke--;
        if (ke == s) {
            ok = false;
            break;
        }
        size_t vs = d + 1;
        while (vs < e && is_space(line[vs]))
            vs++;
        char *key = strndup(line + s, ke - s);
        if (key == NULL) {
            ok = false;
            break;
        }
        for (char *p = key; *p; p++) {
            if (*p >= 'A' && *p <= 'Z')
                *p = (char)(*p + 32);
        }
        /* strict=False: a repeated option replaces the previous one */
        cur = NULL;
        for (size_t k = 0; k < ini->len; k++) {
            if (strcmp(ini->v[k].section, section) == 0 && strcmp(ini->v[k].key, key) == 0) {
                cur = &ini->v[k];
                free(key);
                cur->val.len = 0;
                break;
            }
        }
        if (cur == NULL) {
            if (ini->len == ini->cap) {
                size_t ncap = ini->cap ? ini->cap * 2 : 32;
                struct ini_opt *nv = realloc(ini->v, ncap * sizeof(*nv));
                if (nv == NULL) {
                    free(key);
                    ok = false;
                    break;
                }
                ini->v = nv;
                ini->cap = ncap;
            }
            cur = &ini->v[ini->len];
            memset(cur, 0, sizeof(*cur));
            cur->section = strdup(section);
            cur->key = key;
            ini->len++;
            if (cur->section == NULL) {
                ok = false;
                break;
            }
        }
        ks_pybuf_add(&cur->val, line + vs, e - vs);
        if (cur->val.s)
            cur->val.s[cur->val.len] = '\0';
    }
    free(section);
    /* _join_multiline_values(): '\n'.join(val).rstrip() */
    for (size_t k = 0; k < ini->len; k++) {
        struct ks_pybuf *b = &ini->v[k].val;
        if (b->oom)
            ok = false;
        while (b->s && b->len > 0 && (is_space(b->s[b->len - 1]) || b->s[b->len - 1] == '\n'))
            b->s[--b->len] = '\0';
    }
    return ok;
}

/* ---- Exec -------------------------------------------------------------- */

static bool flatpak_char(char c)
{
    /* [a-zA-Z0-9-_\/\.\+]: "9-_" is the range 0x39-0x5F */
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '_') ||
           c == '/' || c == '.' || c == '+';
}

char *ks_desktop_parse_exec(const char *cmd)
{
    /* ^/usr/[s]*bin/flatpak.*--command=(...)+: the greedy .* takes the
     * last --command= followed by an allowed character */
    if (strncmp(cmd, "/usr/", 5) == 0) {
        const char *p = cmd + 5;
        while (*p == 's')
            p++;
        if (strncmp(p, "bin/flatpak", 11) == 0) {
            const char *best = NULL;
            for (const char *q = strstr(p + 11, "--command="); q != NULL;
                 q = strstr(q + 1, "--command=")) {
                if (flatpak_char(q[10]))
                    best = q + 10;
            }
            if (best != NULL) {
                size_t l = 0;
                while (flatpak_char(best[l]))
                    l++;
                return strndup(best, l);
            }
        }
    }

    struct ks_pybuf b = {0};
    ks_pybuf_add(&b, "", 0);
    /* remove stuff like %U: %[a-zA-Z]+ */
    for (const char *p = cmd; *p;) {
        if (p[0] == '%' && ((p[1] >= 'a' && p[1] <= 'z') || (p[1] >= 'A' && p[1] <= 'Z'))) {
            p++;
            while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))
                p++;
            continue;
        }
        ks_pybuf_add(&b, p, 1);
        p++;
    }
    char *s = ks_pybuf_finish(&b);
    if (s == NULL)
        return NULL;
    /* ^env\s+[^\s]+\s */
    if (strncmp(s, "env", 3) == 0 && s[3] != '\0' && strchr(" \t\n\r\f\v", s[3])) {
        const char *p = s + 3;
        while (*p && strchr(" \t\n\r\f\v", *p))
            p++;
        const char *w = p;
        while (*p && !strchr(" \t\n\r\f\v", *p))
            p++;
        /* [^\s]+ backtracks so that \s can match */
        if (p > w && *p != '\0')
            memmove(s, p + 1, strlen(p + 1) + 1);
    }
    /* cmd.split(' ')[0].strip() */
    char *sp = strchr(s, ' ');
    if (sp)
        *sp = '\0';
    size_t st = 0, en = strlen(s);
    while (st < en && strchr(" \t\n\r\f\v", s[st]))
        st++;
    while (en > st && strchr(" \t\n\r\f\v", s[en - 1]))
        en--;
    memmove(s, s + st, en - st);
    s[en - st] = '\0';
    /* ["']+ */
    size_t o = 0;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] != '"' && s[i] != '\'')
            s[o++] = s[i];
    }
    s[o] = '\0';
    /* resolve it in $PATH */
    if (s[0] != '\0' && s[0] != '/') {
        const char *path = getenv("PATH");
        if (path == NULL)
            path = "";
        for (;;) {
            const char *c = strchr(path, ':');
            size_t dl = c ? (size_t)(c - path) : strlen(path);
            char full[PATH_MAX];
            int w;
            /* os.path.join(dir, cmd) */
            if (dl == 0)
                w = snprintf(full, sizeof(full), "%s", s);
            else if (path[dl - 1] == '/')
                w = snprintf(full, sizeof(full), "%.*s%s", (int)dl, path, s);
            else
                w = snprintf(full, sizeof(full), "%.*s/%s", (int)dl, path, s);
            if (w > 0 && (size_t)w < sizeof(full) && access(full, F_OK) == 0) {
                char *r = strdup(full);
                if (r != NULL) {
                    free(s);
                    s = r;
                }
                break;
            }
            if (c == NULL)
                break;
            path = c + 1;
        }
    }
    return s;
}

/* ---- icons ------------------------------------------------------------- */

/* discover_app_icon(): the first file of /usr/share/icons/<theme>/<size>/apps
 * whose path contains `name`. */
static char *discover_icon(const char *base, const char *name)
{
    DIR *d1 = opendir(base);
    if (d1 == NULL)
        return NULL;
    char *found = NULL;
    struct dirent *e1;
    while (found == NULL && (e1 = readdir(d1)) != NULL) {
        if (e1->d_name[0] == '.')
            continue;
        char p1[PATH_MAX];
        snprintf(p1, sizeof(p1), "%s/%s", base, e1->d_name);
        DIR *d2 = opendir(p1);
        if (d2 == NULL)
            continue;
        struct dirent *e2;
        while (found == NULL && (e2 = readdir(d2)) != NULL) {
            if (e2->d_name[0] == '.')
                continue;
            char p2[PATH_MAX];
            if (snprintf(p2, sizeof(p2), "%s/%s/apps", p1, e2->d_name) >= (int)sizeof(p2))
                continue;
            DIR *d3 = opendir(p2);
            if (d3 == NULL)
                continue;
            struct dirent *e3;
            while ((e3 = readdir(d3)) != NULL) {
                if (e3->d_name[0] == '.')
                    continue;
                char p3[PATH_MAX];
                if (snprintf(p3, sizeof(p3), "%s/%s", p2, e3->d_name) >= (int)sizeof(p3))
                    continue;
                if (strstr(p3, name) != NULL) {
                    found = strdup(p3);
                    break;
                }
            }
            closedir(d3);
        }
        closedir(d2);
    }
    closedir(d1);
    return found;
}

/* ---- the parser -------------------------------------------------------- */

static void set_app(struct ks_desktop *d, const char *key, struct app *a)
{
    void *old = NULL;
    a->refs++;
    if (ks_strmap_set(&d->apps, key, a, &old) < 0) {
        a->refs--;
        return;
    }
    app_unref(old);
}

static const char *base_name(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

bool ks_desktop_parse_file(struct ks_desktop *d, const char *path)
{
    char err[256];
    size_t len;
    char *text = ks_read_file(path, DESKTOP_MAX_SIZE, &len, err, sizeof(err));
    if (text == NULL)
        return false;
    bool ok = ks_desktop_parse_text(d, path, text, len);
    free(text);
    return ok;
}

bool ks_desktop_parse_text(struct ks_desktop *d, const char *path, const char *text, size_t len)
{
    struct ini ini = {0};
    bool ok = ks_utf8_valid(text, len) && ini_parse(&ini, text, len);
    if (!ok) {
        ks_debug("Exception parsing .desktop file %s", path);
        ini_free(&ini);
        return false;
    }
    const char *cmdline = ini_get(&ini, "Desktop Entry", "exec");
    if (cmdline == NULL) {
        ini_free(&ini);
        return false;
    }
    const char *name = ini_get(&ini, "Desktop Entry", "Name");
    if (name != NULL && strcmp(name, "flatpak") == 0) {
        ini_free(&ini);
        return false;
    }
    /* get_app_description() */
    char key[96];
    snprintf(key, sizeof(key), "Comment[%s]", d->locale_country);
    const char *desc = ini_get(&ini, "Desktop Entry", key);
    if (desc == NULL) {
        snprintf(key, sizeof(key), "Comment[%s]", d->locale);
        desc = ini_get(&ini, "Desktop Entry", key);
    }
    if (desc == NULL)
        desc = ini_get(&ini, "Desktop Entry", "Comment");

    struct app *a = calloc(1, sizeof(*a));
    char *cmd = ks_desktop_parse_exec(cmdline);
    const char *icon = ini_get(&ini, "Desktop Entry", "Icon");
    /* the basename without ".desktop" */
    char *basename = strdup(base_name(path));
    if (a == NULL || cmd == NULL || basename == NULL) {
        free(a);
        free(cmd);
        free(basename);
        ini_free(&ini);
        return false;
    }
    size_t bl = strlen(basename);
    basename[bl >= 8 ? bl - 8 : 0] = '\0';
    a->name = name ? strdup(name) : NULL;
    a->desc = desc ? strdup(desc) : NULL;
    a->path = strdup(path);
    if (icon != NULL)
        a->icon = strdup(icon);
    else if ((a->icon = discover_icon(d->icons_dir, basename)) == NULL)
        a->icon = strdup(KS_DESKTOP_TERMINAL_ICON);
    ini_free(&ini);

    set_app(d, cmd, a);
    set_app(d, basename, a);
    struct stat st;
    if (lstat(cmd, &st) == 0 && S_ISLNK(st.st_mode)) {
        char real[PATH_MAX];
        if (realpath(cmd, real) != NULL)
            set_app(d, real, a);
    }
    free(cmd);
    free(basename);
    if (a->refs == 0)
        app_unref(a);
    return true;
}

static void parse_dir(struct ks_desktop *d, const char *dir)
{
    DIR *dh = opendir(dir);
    if (dh == NULL)
        return;
    struct dirent *e;
    /* glob('*.desktop'): directory order, no hidden files */
    while ((e = readdir(dh)) != NULL) {
        size_t l = strlen(e->d_name);
        if (e->d_name[0] == '.' || l < 8 || strcmp(e->d_name + l - 8, ".desktop") != 0)
            continue;
        char p[PATH_MAX];
        if (snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) < (int)sizeof(p))
            ks_desktop_parse_file(d, p);
    }
    closedir(dh);
}

int ks_desktop_init(struct ks_desktop *d, const char *xdg_data_dirs, const char *locale)
{
    memset(d, 0, sizeof(*d));
    d->inotify_fd = -1;
    d->icons_dir = KS_DESKTOP_ICONS_DIR;
    ks_strmap_init(&d->apps);

    /* get_locale(): locale.getlocale()[0], and its language */
    const char *loc = locale ? locale : setlocale(LC_MESSAGES, NULL);
    if (loc == NULL || strcmp(loc, "C") == 0 || strcmp(loc, "POSIX") == 0)
        loc = "";
    snprintf(d->locale, sizeof(d->locale), "%s", loc);
    d->locale[strcspn(d->locale, ".@")] = '\0';
    size_t cl = strcspn(d->locale, "_");
    if (cl >= sizeof(d->locale_country))
        cl = sizeof(d->locale_country) - 1;
    memcpy(d->locale_country, d->locale, cl);
    d->locale_country[cl] = '\0';

    const char *dirs = xdg_data_dirs ? xdg_data_dirs : getenv("XDG_DATA_DIRS");
    if (dirs == NULL)
        dirs = "/usr/share/";
    int n = 1;
    for (const char *p = dirs; *p; p++)
        n += *p == ':';
    d->dirs = calloc((size_t)n, sizeof(*d->dirs));
    if (d->dirs == NULL)
        return -1;
    const char *p = dirs;
    for (int i = 0; i < n; i++) {
        const char *c = strchr(p, ':');
        size_t l = c ? (size_t)(c - p) : strlen(p);
        char buf[PATH_MAX];
        /* os.path.join(d, 'applications') */
        if (l == 0)
            snprintf(buf, sizeof(buf), "applications");
        else if (p[l - 1] == '/')
            snprintf(buf, sizeof(buf), "%.*sapplications", (int)l, p);
        else
            snprintf(buf, sizeof(buf), "%.*s/applications", (int)l, p);
        d->dirs[d->ndirs] = strdup(buf);
        if (d->dirs[d->ndirs] != NULL)
            d->ndirs++;
        p = c ? c + 1 : p + l;
    }
    for (int i = 0; i < d->ndirs; i++)
        parse_dir(d, d->dirs[i]);
    return 0;
}

void ks_desktop_free(struct ks_desktop *d)
{
    ks_strmap_clear(&d->apps, app_unref);
    for (int i = 0; i < d->ndirs; i++)
        free(d->dirs[i]);
    free(d->dirs);
    free(d->wds);
    if (d->inotify_fd >= 0)
        close(d->inotify_fd);
    memset(d, 0, sizeof(*d));
    d->inotify_fd = -1;
}

void ks_app_info_free(struct ks_app_info *i)
{
    if (i == NULL)
        return;
    free(i->name);
    free(i->icon);
    free(i->description);
    free(i->desktop_path);
    free(i);
}

struct ks_app_info *ks_desktop_info_by_path(const struct ks_desktop *d, const char *path,
                                            const char *default_icon)
{
    struct ks_app_info *i = calloc(1, sizeof(*i));
    if (i == NULL)
        return NULL;
    const char *def_name = base_name(path);
    for (size_t k = 0; k < sizeof(fixes) / sizeof(fixes[0]); k++) {
        if (strcmp(path, fixes[k][0]) == 0) {
            path = fixes[k][1];
            break;
        }
    }
    const struct app *a = ks_strmap_get(&d->apps, path);
    if (a == NULL)
        a = ks_strmap_get(&d->apps, def_name);
    if (a != NULL) {
        /* a .desktop without Name gives None upstream; "" here */
        i->name = strdup(a->name ? a->name : "");
        i->icon = strdup(a->icon ? a->icon : default_icon);
        i->description = strdup(a->desc ? a->desc : "");
        i->desktop_path = a->path ? strdup(a->path) : NULL;
    } else {
        i->name = strdup(def_name);
        i->icon = discover_icon(d->icons_dir, def_name);
        if (i->icon == NULL)
            i->icon = strdup(KS_DESKTOP_TERMINAL_ICON);
        i->description = strdup("");
    }
    if (i->name == NULL || i->icon == NULL || i->description == NULL) {
        ks_app_info_free(i);
        return NULL;
    }
    return i;
}

int ks_desktop_watch(struct ks_desktop *d)
{
    d->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (d->inotify_fd < 0)
        return -1;
    d->wds = calloc((size_t)(d->ndirs ? d->ndirs : 1), sizeof(*d->wds));
    if (d->wds == NULL)
        return -1;
    for (int i = 0; i < d->ndirs; i++)
        d->wds[i] = inotify_add_watch(d->inotify_fd, d->dirs[i], IN_CLOSE_WRITE | IN_DELETE);
    return d->inotify_fd;
}

void ks_desktop_on_inotify(struct ks_desktop *d)
{
    _Alignas(struct inotify_event) char buf[4096];
    for (;;) {
        ssize_t n = read(d->inotify_fd, buf, sizeof(buf));
        if (n <= 0)
            return;
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *ev = (struct inotify_event *)(void *)p;
            p += sizeof(*ev) + ev->len;
            /* IN_DELETE: upstream looks for the path in the description
             * field and never finds it; nothing to do */
            if (!(ev->mask & IN_CLOSE_WRITE) || ev->len == 0)
                continue;
            for (int i = 0; i < d->ndirs; i++) {
                if (d->wds[i] != ev->wd)
                    continue;
                char path[PATH_MAX];
                if (snprintf(path, sizeof(path), "%s/%s", d->dirs[i], ev->name) <
                    (int)sizeof(path))
                    ks_desktop_parse_file(d, path);
            }
        }
    }
}
