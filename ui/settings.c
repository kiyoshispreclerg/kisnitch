/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * QSettings' INI format (Qt's qsettings.cpp: readIniFile, writeIniFile,
 * iniEscapedKey, iniUnescapedKey, iniEscapedString,
 * iniUnescapedStringList) and the defaults of upstream
 * ui/opensnitch/config.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/settings.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/unicode.h"
#include "ui/pyjson.h"

#define SETTINGS_MAX_SIZE (16 * 1024 * 1024)
/* Keys without a group live in "" and are written under [General]; a
 * group really named "General" is written as [%General]. */
#define GENERAL "General"
#define ROOT ""

static const char hex_digits[] = "0123456789ABCDEF";

/* ---- entries ----------------------------------------------------------- */

static void free_entry(struct ks_setting *e)
{
    free(e->group);
    free(e->key);
    free(e->raw);
}

static void free_entries(struct ks_setting *v, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free_entry(&v[i]);
    free(v);
}

/* "global/default_timeout" -> group "global", key "default_timeout";
 * "statsDialog" -> "General", "statsDialog". */
static int split_key(const char *full, char **group, char **key)
{
    const char *slash = strchr(full, '/');
    if (slash == NULL || slash == full) {
        *group = strdup(ROOT);
        *key = strdup(slash ? full + 1 : full);
    } else {
        *group = strndup(full, (size_t)(slash - full));
        *key = strdup(slash + 1);
    }
    if (*group == NULL || *key == NULL) {
        free(*group);
        free(*key);
        return -1;
    }
    return 0;
}

static struct ks_setting *find(struct ks_setting *v, size_t n, const char *group, const char *key)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(v[i].group, group) == 0 && strcmp(v[i].key, key) == 0)
            return &v[i];
    }
    return NULL;
}

static const struct ks_setting *find_full(const struct ks_settings *s, const char *full)
{
    char *group, *key;
    if (split_key(full, &group, &key) < 0)
        return NULL;
    const struct ks_setting *e = NULL;
    /* pending changes win: they're what QSettings returns before a sync */
    e = find(s->pending, s->npending, group, key);
    if (e == NULL)
        e = find(s->items, s->len, group, key);
    free(group);
    free(key);
    return e;
}

/* Sets (group, key) = raw in the list, taking ownership of the strings.
 * A new key goes after the last one of its group, or at the end. */
static int put(struct ks_setting **v, size_t *n, size_t *cap, char *group, char *key, char *raw)
{
    struct ks_setting *e = find(*v, *n, group, key);
    if (e != NULL) {
        free(e->raw);
        e->raw = raw;
        free(group);
        free(key);
        return 0;
    }
    if (*n == *cap) {
        size_t ncap = *cap ? *cap * 2 : 32;
        struct ks_setting *nv = realloc(*v, ncap * sizeof(*nv));
        if (nv == NULL) {
            free(group);
            free(key);
            free(raw);
            return -1;
        }
        *v = nv;
        *cap = ncap;
    }
    size_t at = *n;
    for (size_t i = *n; i > 0; i--) {
        if (strcmp((*v)[i - 1].group, group) == 0) {
            at = i;
            break;
        }
    }
    memmove(&(*v)[at + 1], &(*v)[at], (*n - at) * sizeof(**v));
    (*v)[at] = (struct ks_setting){group, key, raw};
    (*n)++;
    return 0;
}

/* ---- keys -------------------------------------------------------------- */

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* iniUnescapedKey: %XX (Latin-1), %UXXXX (UTF-16 unit), "\" -> "/". */
static char *unescape_key_raw(const char *s, size_t n);

/* Qt 6 reads the file as UTF-8: invalid bytes are U+FFFD. */
static char *unescape_key(const char *s, size_t n)
{
    char *k = unescape_key_raw(s, n);
    if (k == NULL || ks_utf8_valid(k, strlen(k)))
        return k;
    size_t len;
    char *clean = ks_utf8_sanitize(k, strlen(k), &len);
    free(k);
    return clean;
}

/* "%UXXXX" at s[i]: its value, or -1 */
static long utf16_escape(const char *s, size_t n, size_t i)
{
    if (!(i + 5 < n && s[i] == '%' && s[i + 1] == 'U'))
        return -1;
    long v = 0;
    for (size_t k = i + 2; k < i + 6; k++) {
        if (hexval(s[k]) < 0)
            return -1;
        v = v << 4 | hexval(s[k]);
    }
    return v;
}

static char *unescape_key_raw(const char *s, size_t n)
{
    char *out = malloc(n * 3 + 1);
    if (out == NULL)
        return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\\') {
            out[o++] = '/';
            i++;
        } else if (c == '%' && utf16_escape(s, n, i) >= 0) {
            uint32_t r = (uint32_t)utf16_escape(s, n, i);
            i += 6;
            /* UTF-16: a surrogate pair is two escapes */
            if (r >= 0xD800 && r <= 0xDBFF && i < n && s[i] == '%' &&
                utf16_escape(s, n, i) >= 0xDC00 && utf16_escape(s, n, i) <= 0xDFFF) {
                r = 0x10000 + ((r - 0xD800) << 10) + ((uint32_t)utf16_escape(s, n, i) - 0xDC00);
                i += 6;
            } else if (r >= 0xD800 && r <= 0xDFFF) {
                r = 0xFFFD;
            }
            o += ks_utf8_encode(r, out + o);
        } else if (c == '%' && i + 2 < n && hexval(s[i + 1]) >= 0 && hexval(s[i + 2]) >= 0) {
            o += ks_utf8_encode((uint32_t)(hexval(s[i + 1]) << 4 | hexval(s[i + 2])), out + o);
            i += 3;
        } else {
            out[o++] = (char)c;
            i++;
        }
    }
    out[o] = '\0';
    return out;
}

/* iniEscapedKey */
static void escape_key(struct ks_pybuf *b, const char *key)
{
    size_t n = strlen(key);
    for (size_t i = 0; i < n;) {
        uint32_t r;
        size_t l = ks_utf8_decode(key + i, n - i, &r);
        i += l ? l : 1;
        char tmp[8];
        if (r == '/') {
            ks_pybuf_add(b, "\\", 1);
        } else if ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
                   r == '_' || r == '-' || r == '.') {
            tmp[0] = (char)r;
            ks_pybuf_add(b, tmp, 1);
        } else if (r <= 0xFF) {
            tmp[0] = '%';
            tmp[1] = hex_digits[r / 16];
            tmp[2] = hex_digits[r % 16];
            ks_pybuf_add(b, tmp, 3);
        } else {
            /* UTF-16 units: a surrogate pair above U+FFFF */
            uint32_t units[2] = {r, 0};
            int nu = 1;
            if (r > 0xFFFF) {
                units[0] = 0xD800 + ((r - 0x10000) >> 10);
                units[1] = 0xDC00 + ((r - 0x10000) & 0x3FF);
                nu = 2;
            }
            for (int u = 0; u < nu; u++) {
                uint32_t x = units[u];
                snprintf(tmp, sizeof(tmp), "%%U%c%c%c%c", hex_digits[(x >> 12) & 15],
                         hex_digits[(x >> 8) & 15], hex_digits[(x >> 4) & 15], hex_digits[x & 15]);
                ks_pybuf_adds(b, tmp);
            }
        }
    }
}

/* ---- values ------------------------------------------------------------ */

char *ks_settings_escape(const char *value)
{
    struct ks_pybuf b = {0};
    bool needs_quotes = false, escape_next_if_digit = false;
    size_t n = strlen(value);
    if (value[0] == '@')
        ks_pybuf_add(&b, "@", 1); /* variantToString: "@" -> "@@" */
    for (size_t i = 0; i < n;) {
        uint32_t ch;
        size_t start = i;
        size_t l = ks_utf8_decode(value + i, n - i, &ch);
        i += l ? l : 1;
        char tmp[16];
        if (ch == ';' || ch == ',' || ch == '=')
            needs_quotes = true;
        if (escape_next_if_digit && hexval((int)ch) >= 0 && ch < 0x80) {
            snprintf(tmp, sizeof(tmp), "\\x%x", (unsigned)ch);
            ks_pybuf_adds(&b, tmp);
            continue;
        }
        escape_next_if_digit = false;
        switch (ch) {
        case '\0': ks_pybuf_adds(&b, "\\0"); escape_next_if_digit = true; break;
        case '\a': ks_pybuf_adds(&b, "\\a"); break;
        case '\b': ks_pybuf_adds(&b, "\\b"); break;
        case '\f': ks_pybuf_adds(&b, "\\f"); break;
        case '\n': ks_pybuf_adds(&b, "\\n"); break;
        case '\r': ks_pybuf_adds(&b, "\\r"); break;
        case '\t': ks_pybuf_adds(&b, "\\t"); break;
        case '\v': ks_pybuf_adds(&b, "\\v"); break;
        case '"':
        case '\\':
            tmp[0] = '\\';
            tmp[1] = (char)ch;
            ks_pybuf_add(&b, tmp, 2);
            break;
        default:
            if (ch <= 0x1F) {
                snprintf(tmp, sizeof(tmp), "\\x%x", (unsigned)ch);
                ks_pybuf_adds(&b, tmp);
                escape_next_if_digit = true;
            } else {
                /* Qt 6 writes UTF-8 */
                ks_pybuf_add(&b, value + start, i - start);
            }
        }
    }
    if (b.s == NULL)
        ks_pybuf_add(&b, "", 0);
    if (!b.oom && (needs_quotes || (b.len > 0 && (b.s[0] == ' ' || b.s[b.len - 1] == ' ')))) {
        struct ks_pybuf q = {0};
        ks_pybuf_add(&q, "\"", 1);
        ks_pybuf_add(&q, b.s, b.len);
        ks_pybuf_add(&q, "\"", 1);
        free(b.s);
        return ks_pybuf_finish(&q);
    }
    return ks_pybuf_finish(&b);
}

static void add_cp(struct ks_pybuf *b, uint32_t cp)
{
    char tmp[4];
    ks_pybuf_add(b, tmp, ks_utf8_encode(cp & 0xFFFF, tmp));
}

/* Trailing spaces of the current value go, but not escaped ones nor those
 * before `limit`. */
static void chop_trailing(struct ks_pybuf *b, size_t limit)
{
    while (b->len > limit && (b->s[b->len - 1] == ' ' || b->s[b->len - 1] == '\t'))
        b->s[--b->len] = '\0';
}

/* iniUnescapedStringList; a list comes back joined with ", ". */
char *ks_settings_unescape(const char *raw)
{
    static const char codes[][2] = {{'a', '\a'}, {'b', '\b'}, {'f', '\f'}, {'n', '\n'},
                                    {'r', '\r'}, {'t', '\t'}, {'v', '\v'}, {'"', '"'},
                                    {'?', '?'},  {'\'', '\''}, {'\\', '\\'}};
    struct ks_pybuf cur = {0}, list = {0};
    bool is_list = false, in_quotes = false, quoted = false;
    size_t to = strlen(raw), i = 0, chop_limit = 0;
    ks_pybuf_add(&cur, "", 0);

    while (i < to && (raw[i] == ' ' || raw[i] == '\t'))
        i++;
    chop_limit = cur.len;
    while (i < to) {
        char ch = raw[i];
        if (ch == '\\') {
            i++;
            if (i >= to)
                break;
            ch = raw[i++];
            bool done = false;
            for (size_t j = 0; j < sizeof(codes) / sizeof(codes[0]); j++) {
                if (ch == codes[j][0]) {
                    ks_pybuf_add(&cur, &codes[j][1], 1);
                    done = true;
                    break;
                }
            }
            if (!done && ch == 'x' && i < to && hexval(raw[i]) >= 0) {
                uint32_t v = 0;
                while (i < to && hexval(raw[i]) >= 0)
                    v = ((v << 4) + (uint32_t)hexval(raw[i++])) & 0xFFFFF;
                add_cp(&cur, v);
            } else if (!done && ch >= '0' && ch <= '7') {
                uint32_t v = (uint32_t)(ch - '0');
                while (i < to && raw[i] >= '0' && raw[i] <= '7')
                    v = ((v << 3) + (uint32_t)(raw[i++] - '0')) & 0xFFFFF;
                add_cp(&cur, v);
            } else if (!done && (ch == '\n' || ch == '\r')) {
                if (i < to && (raw[i] == '\n' || raw[i] == '\r') && raw[i] != ch)
                    i++;
            }
            chop_limit = cur.len;
        } else if (ch == '"') {
            i++;
            quoted = true;
            in_quotes = !in_quotes;
            if (!in_quotes) {
                while (i < to && (raw[i] == ' ' || raw[i] == '\t'))
                    i++;
                chop_limit = cur.len;
            }
        } else if (ch == ',' && !in_quotes) {
            if (!quoted)
                chop_trailing(&cur, chop_limit);
            if (is_list)
                ks_pybuf_adds(&list, ", ");
            is_list = true;
            ks_pybuf_add(&list, cur.s, cur.len);
            cur.len = 0;
            cur.s[0] = '\0';
            quoted = false;
            i++;
            while (i < to && (raw[i] == ' ' || raw[i] == '\t'))
                i++;
            chop_limit = 0;
        } else {
            size_t j = i + 1;
            while (j < to && raw[j] != '\\' && raw[j] != '"' && raw[j] != ',')
                j++;
            ks_pybuf_add(&cur, raw + i, j - i);
            i = j;
        }
    }
    if (!quoted)
        chop_trailing(&cur, chop_limit);
    char *r;
    if (!is_list) {
        r = ks_pybuf_finish(&cur);
    } else {
        ks_pybuf_adds(&list, ", ");
        ks_pybuf_add(&list, cur.s, cur.len);
        free(cur.s);
        r = ks_pybuf_finish(&list);
    }
    /* Qt 6 decodes the file as UTF-8 */
    if (r != NULL && !ks_utf8_valid(r, strlen(r))) {
        size_t len;
        char *clean = ks_utf8_sanitize(r, strlen(r), &len);
        free(r);
        r = clean;
    }
    return r;
}

/* ---- file -------------------------------------------------------------- */

int ks_settings_default_path(char *buf, size_t len)
{
    const char *xdg = getenv("XDG_CONFIG_HOME");
    int n;
    if (xdg != NULL && xdg[0] != '\0') {
        n = snprintf(buf, len, "%s/opensnitch/settings.conf", xdg);
    } else {
        const char *home = getenv("HOME");
        if (home == NULL || home[0] == '\0')
            return -1;
        n = snprintf(buf, len, "%s/.config/opensnitch/settings.conf", home);
    }
    return (n < 0 || (size_t)n >= len) ? -1 : 0;
}

static size_t line_end(const char *t, size_t i, size_t n)
{
    /* a backslash escapes the next character, newlines included */
    while (i < n && t[i] != '\n' && t[i] != '\r') {
        if (t[i] == '\\' && i + 1 < n)
            i++;
        i++;
    }
    return i;
}

int ks_settings_parse(struct ks_settings *s, const char *text, size_t n)
{
    /* a NUL ends a corrupt file */
    const char *nul = memchr(text, '\0', n);
    if (nul != NULL)
        n = (size_t)(nul - text);
    struct ks_setting *v = NULL;
    size_t len = 0, cap = 0;
    char *group = strdup(ROOT);
    if (group == NULL)
        return -1;
    for (size_t i = 0; i < n;) {
        while (i < n && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r'))
            i++;
        if (i >= n)
            break;
        size_t e = line_end(text, i, n);
        const char *line = text + i;
        size_t ll = e - i;
        i = e;
        if (line[0] == ';')
            continue;
        if (line[0] == '[') {
            const char *close = memchr(line, ']', ll);
            size_t gl = close ? (size_t)(close - line - 1) : ll - 1;
            char *g = unescape_key(line + 1, gl);
            if (g == NULL)
                goto oom;
            /* "[General]" is the root, "[%General]" a group named so (in
             * any case, as Qt's readIniSection) */
            if (strcasecmp(g, GENERAL) == 0)
                g[0] = '\0';
            else if (strcasecmp(g, "%" GENERAL) == 0)
                memcpy(g, GENERAL, sizeof(GENERAL));
            free(group);
            group = g;
            continue;
        }
        const char *eq = memchr(line, '=', ll);
        if (eq == NULL)
            continue;
        size_t kl = (size_t)(eq - line);
        while (kl > 0 && (line[kl - 1] == ' ' || line[kl - 1] == '\t'))
            kl--;
        const char *val = eq + 1;
        size_t vl = ll - (size_t)(val - line);
        while (vl > 0 && (*val == ' ' || *val == '\t')) {
            val++;
            vl--;
        }
        while (vl > 0 && (val[vl - 1] == ' ' || val[vl - 1] == '\t') &&
               !(vl >= 2 && val[vl - 2] == '\\'))
            vl--;
        /* a final unpaired backslash means nothing to Qt's unescaping, and
         * written back it would join the next line */
        size_t bs = 0;
        while (bs < vl && val[vl - 1 - bs] == '\\')
            bs++;
        if (bs % 2 == 1)
            vl--;
        char *k = unescape_key(line, kl);
        char *raw = strndup(val, vl);
        char *g = strdup(group);
        if (k == NULL || raw == NULL || g == NULL) {
            free(k);
            free(raw);
            free(g);
            goto oom;
        }
        /* a key with "/" in a group: "a/b" in [g] is "g/a/b" */
        if (put(&v, &len, &cap, g, k, raw) < 0)
            goto oom;
    }
    free(group);
    free_entries(s->items, s->len);
    s->items = v;
    s->len = len;
    s->cap = cap;
    return 0;
oom:
    free(group);
    free_entries(v, len);
    return -1;
}

char *ks_settings_serialize(const struct ks_settings *s)
{
    struct ks_pybuf b = {0};
    bool *done = calloc(s->len ? s->len : 1, sizeof(*done));
    if (done == NULL)
        return NULL;
    bool first = true;
    for (size_t i = 0; i < s->len; i++) {
        if (done[i])
            continue;
        const char *group = s->items[i].group;
        if (!first)
            ks_pybuf_add(&b, "\n", 1);
        first = false;
        ks_pybuf_add(&b, "[", 1);
        if (group[0] == '\0')
            ks_pybuf_adds(&b, GENERAL);
        else if (strcmp(group, GENERAL) == 0)
            ks_pybuf_adds(&b, "%" GENERAL);
        else
            escape_key(&b, group);
        ks_pybuf_add(&b, "]\n", 2);
        for (size_t j = i; j < s->len; j++) {
            if (done[j] || strcmp(s->items[j].group, group) != 0)
                continue;
            done[j] = true;
            escape_key(&b, s->items[j].key);
            ks_pybuf_add(&b, "=", 1);
            ks_pybuf_adds(&b, s->items[j].raw);
            ks_pybuf_add(&b, "\n", 1);
        }
    }
    free(done);
    if (b.s == NULL)
        ks_pybuf_add(&b, "", 0);
    return ks_pybuf_finish(&b);
}

static int load_file(struct ks_settings *s)
{
    char err[256];
    if (s->path == NULL)
        return 0; /* in memory only */
    size_t len;
    char *text = ks_read_file(s->path, SETTINGS_MAX_SIZE, &len, err, sizeof(err));
    if (text == NULL) {
        if (access(s->path, F_OK) != 0 && errno == ENOENT)
            return ks_settings_parse(s, "", 0);
        ks_error("settings: %s", err);
        return -1;
    }
    int rc = ks_settings_parse(s, text, len);
    free(text);
    return rc;
}

int ks_settings_open(struct ks_settings *s, const char *path)
{
    memset(s, 0, sizeof(*s));
    s->path = strdup(path);
    if (s->path == NULL)
        return -1;
    return load_file(s);
}

void ks_settings_close(struct ks_settings *s)
{
    free(s->path);
    free_entries(s->items, s->len);
    free_entries(s->pending, s->npending);
    memset(s, 0, sizeof(*s));
}

int ks_settings_reload(struct ks_settings *s)
{
    return load_file(s);
}

static int mkdirs(const char *path)
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp))
        return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return 0;
}

int ks_settings_sync(struct ks_settings *s)
{
    if (load_file(s) < 0)
        return -1;
    for (size_t i = 0; i < s->npending; i++) {
        struct ks_setting *p = &s->pending[i];
        char *g = strdup(p->group), *k = strdup(p->key), *r = strdup(p->raw);
        if (g == NULL || k == NULL || r == NULL) {
            free(g);
            free(k);
            free(r);
            return -1;
        }
        if (put(&s->items, &s->len, &s->cap, g, k, r) < 0)
            return -1;
    }
    if (s->path == NULL) {
        /* in memory only */
        free_entries(s->pending, s->npending);
        s->pending = NULL;
        s->npending = s->cappending = 0;
        return 0;
    }
    char *text = ks_settings_serialize(s);
    if (text == NULL)
        return -1;
    char tmp[PATH_MAX], err[256];
    int rc = -1;
    if (mkdirs(s->path) == 0 &&
        snprintf(tmp, sizeof(tmp), "%s.XXXXXX", s->path) < (int)sizeof(tmp)) {
        int fd = mkstemp(tmp);
        if (fd >= 0) {
            mode_t um = umask(0);
            umask(um);
            fchmod(fd, 0666 & ~um);
            close(fd);
            if (ks_write_file(tmp, text, strlen(text), 0666 & ~um, err, sizeof(err)) == 0 &&
                rename(tmp, s->path) == 0)
                rc = 0;
            else
                unlink(tmp);
        }
    }
    if (rc < 0)
        ks_error("settings: can't write %s: %s", s->path, strerror(errno));
    free(text);
    free_entries(s->pending, s->npending);
    s->pending = NULL;
    s->npending = s->cappending = 0;
    return rc;
}

/* ---- accessors --------------------------------------------------------- */

bool ks_settings_has(const struct ks_settings *s, const char *key)
{
    return find_full(s, key) != NULL;
}

const char *ks_settings_raw(const struct ks_settings *s, const char *key)
{
    const struct ks_setting *e = find_full(s, key);
    return e ? e->raw : NULL;
}

char *ks_settings_get_string(const struct ks_settings *s, const char *key)
{
    const struct ks_setting *e = find_full(s, key);
    if (e == NULL)
        return NULL;
    char *v = ks_settings_unescape(e->raw);
    if (v != NULL && v[0] == '@' && v[1] == '@')
        memmove(v, v + 1, strlen(v));
    return v;
}

int ks_settings_get_int(const struct ks_settings *s, const char *key, int def)
{
    char *v = ks_settings_get_string(s, key);
    if (v == NULL)
        return def;
    char *end;
    errno = 0;
    long n = strtol(v, &end, 10);
    while (*end == ' ' || *end == '\t')
        end++;
    bool ok = end != v && *end == '\0' && errno == 0 && n >= INT_MIN && n <= INT_MAX;
    free(v);
    return ok ? (int)n : def;
}

bool ks_settings_get_bool(const struct ks_settings *s, const char *key, bool def)
{
    char *v = ks_settings_get_string(s, key);
    if (v == NULL)
        return def;
    bool r = !(v[0] == '\0' || strcmp(v, "0") == 0 || strcasecmp(v, "false") == 0);
    free(v);
    return r;
}

int ks_settings_set_raw(struct ks_settings *s, const char *key, const char *raw)
{
    char *group, *k, *r = strdup(raw);
    if (r == NULL || split_key(key, &group, &k) < 0) {
        free(r);
        return -1;
    }
    return put(&s->pending, &s->npending, &s->cappending, group, k, r);
}

int ks_settings_set_string(struct ks_settings *s, const char *key, const char *value)
{
    char *raw = ks_settings_escape(value);
    if (raw == NULL)
        return -1;
    int rc = ks_settings_set_raw(s, key, raw);
    free(raw);
    return rc < 0 ? -1 : ks_settings_sync(s);
}

int ks_settings_set_int(struct ks_settings *s, const char *key, int value)
{
    char raw[16];
    snprintf(raw, sizeof(raw), "%d", value);
    if (ks_settings_set_raw(s, key, raw) < 0)
        return -1;
    return ks_settings_sync(s);
}

int ks_settings_set_bool(struct ks_settings *s, const char *key, bool value)
{
    if (ks_settings_set_raw(s, key, value ? "true" : "false") < 0)
        return -1;
    return ks_settings_sync(s);
}

int ks_settings_init_defaults(struct ks_settings *s)
{
    bool dirty = false;
    char raw[16];
    if (!ks_settings_has(s, KS_CFG_DEFAULT_TIMEOUT_KEY)) {
        snprintf(raw, sizeof(raw), "%d", KS_CFG_DEFAULT_TIMEOUT);
        dirty |= ks_settings_set_raw(s, KS_CFG_DEFAULT_TIMEOUT_KEY, raw) == 0;
    }
    if (!ks_settings_has(s, KS_CFG_DEFAULT_ACTION_KEY)) {
        snprintf(raw, sizeof(raw), "%d", KS_CFG_ACTION_DENY_IDX);
        dirty |= ks_settings_set_raw(s, KS_CFG_DEFAULT_ACTION_KEY, raw) == 0;
    }
    if (!ks_settings_has(s, KS_CFG_DEFAULT_DURATION_KEY)) {
        snprintf(raw, sizeof(raw), "%d", KS_CFG_DEFAULT_DURATION_IDX);
        dirty |= ks_settings_set_raw(s, KS_CFG_DEFAULT_DURATION_KEY, raw) == 0;
    }
    if (!ks_settings_has(s, KS_CFG_DEFAULT_TARGET_KEY)) {
        snprintf(raw, sizeof(raw), "%d", KS_CFG_DEFAULT_TARGET_PROCESS);
        dirty |= ks_settings_set_raw(s, KS_CFG_DEFAULT_TARGET_KEY, raw) == 0;
    }
    if (!ks_settings_has(s, KS_CFG_DEFAULT_DB_TYPE_KEY)) {
        snprintf(raw, sizeof(raw), "%d", KS_CFG_DB_TYPE_MEMORY);
        dirty |= ks_settings_set_raw(s, KS_CFG_DEFAULT_DB_TYPE_KEY, raw) == 0;
        dirty |= ks_settings_set_raw(s, KS_CFG_DEFAULT_DB_FILE_KEY, KS_CFG_DB_IN_MEMORY) == 0;
        dirty |= ks_settings_set_raw(s, KS_CFG_DEFAULT_DB_JRNL_WAL, "false") == 0;
    }
    return dirty ? ks_settings_sync(s) : 0;
}
