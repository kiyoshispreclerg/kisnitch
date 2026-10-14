/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of slugify() from python-slugify (slugify/slugify.py), as called by
 * the upstream UI: slugify(text) with every argument at its default.
 *
 * Copyright (C) Val Neekman @ Neekware Inc. (python-slugify, MIT).
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/slug.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/unicode.h"
#include "ui/slug_tables.h"

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

struct cps {
    uint32_t *v;
    size_t len, cap;
    bool oom;
};

static void push(struct cps *c, uint32_t cp)
{
    if (c->oom)
        return;
    if (c->len == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 64;
        uint32_t *nv = realloc(c->v, ncap * sizeof(*nv));
        if (nv == NULL) {
            c->oom = true;
            return;
        }
        c->v = nv;
        c->cap = ncap;
    }
    c->v[c->len++] = cp;
}

static void push_str(struct cps *c, const char *s)
{
    for (; *s; s++)
        push(c, (unsigned char)*s);
}

static const char *lookup_cp(const struct ks_slug_cp *t, size_t n, uint32_t cp)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (t[mid].cp == cp)
            return t[mid].s;
        if (t[mid].cp < cp)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

static bool lookup_entity(const uint32_t *name, size_t len, uint32_t *cp)
{
    char buf[16];
    if (len == 0 || len >= sizeof(buf))
        return false;
    for (size_t i = 0; i < len; i++) {
        if (name[i] >= 0x80)
            return false;
        buf[i] = (char)name[i];
    }
    buf[len] = '\0';
    size_t lo = 0, hi = NELEM(ks_slug_entities);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(ks_slug_entities[mid].name, buf);
        if (c == 0) {
            *cp = ks_slug_entities[mid].cp;
            return true;
        }
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return false;
}

static bool is_digit(uint32_t c)
{
    return c >= '0' && c <= '9';
}

static int hex_val(uint32_t c)
{
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A' + 10);
    return -1;
}

/* Finds "&#<digits>;" (hex: "&#x<hexdigits>;") at `i`: returns the length
 * of the reference and its value (saturated), or 0. */
static size_t numeric_ref(const struct cps *in, size_t i, bool hex, uint64_t *val)
{
    const uint32_t *s = in->v;
    size_t n = in->len, j = i;
    if (j + 2 >= n || s[j] != '&' || s[j + 1] != '#')
        return 0;
    j += 2;
    if (hex) {
        if (s[j] != 'x')
            return 0;
        j++;
    }
    size_t start = j;
    uint64_t v = 0;
    while (j < n && (hex ? hex_val(s[j]) >= 0 : is_digit(s[j]))) {
        int d = hex ? hex_val(s[j]) : (int)(s[j] - '0');
        if (v < (1ull << 40))
            v = v * (hex ? 16 : 10) + (uint64_t)d;
        j++;
    }
    if (j == start || j >= n || s[j] != ';')
        return 0;
    *val = v;
    return j + 1 - i;
}

/* DECIMAL_PATTERN.sub / HEX_PATTERN.sub(lambda m: chr(int(...))). Python
 * wraps each sub in try/except: one reference beyond U+10FFFF makes chr()
 * raise, and then none of them is replaced. */
static void numeric_refs(struct cps *in, bool hex)
{
    uint64_t v;
    for (size_t i = 0; i < in->len; i++) {
        size_t l = numeric_ref(in, i, hex, &v);
        if (l > 0 && v > 0x10FFFF)
            return;
        if (l > 0)
            i += l - 1;
    }
    struct cps out = {0};
    for (size_t i = 0; i < in->len; i++) {
        size_t l = numeric_ref(in, i, hex, &v);
        if (l > 0) {
            push(&out, (uint32_t)v);
            i += l - 1;
        } else {
            push(&out, in->v[i]);
        }
    }
    free(in->v);
    *in = out;
}

/* CHAR_ENTITY_PATTERN: "&(name1|name2|...);", an exact, case-sensitive
 * entity name. */
static void named_refs(struct cps *in)
{
    struct cps out = {0};
    for (size_t i = 0; i < in->len; i++) {
        uint32_t cp;
        if (in->v[i] == '&') {
            size_t j = i + 1;
            while (j < in->len && j - i <= 16 && in->v[j] != ';' && in->v[j] != '&')
                j++;
            if (j < in->len && in->v[j] == ';' && lookup_entity(&in->v[i + 1], j - i - 1, &cp)) {
                push(&out, cp);
                i = j;
                continue;
            }
        }
        push(&out, in->v[i]);
    }
    free(in->v);
    *in = out;
}

char *ks_slugify(const char *text)
{
    struct cps a = {0}, b = {0};
    size_t n = strlen(text);

    /* QUOTE_PATTERN ([']+) -> "-", then unidecode. */
    for (size_t i = 0; i < n;) {
        uint32_t r;
        size_t l = ks_utf8_decode(text + i, n - i, &r);
        i += l ? l : 1;
        if (r == '\'') {
            if (a.len == 0 || a.v[a.len - 1] != '\'' + 0x100)
                push(&a, '\'' + 0x100); /* a quote run, replaced below */
            continue;
        }
        if (r < 0x80) {
            push(&a, r);
            continue;
        }
        const char *t = lookup_cp(ks_slug_unidecode, NELEM(ks_slug_unidecode), r);
        push_str(&a, t != NULL ? t : " ");
    }
    for (size_t i = 0; i < a.len; i++) {
        if (a.v[i] == '\'' + 0x100)
            a.v[i] = '-';
    }

    /* HTML entities: names, then decimal, then hexadecimal references. */
    if (!a.oom)
        named_refs(&a);
    if (!a.oom)
        numeric_refs(&a, false);
    if (!a.oom)
        numeric_refs(&a, true);

    /* NFKD and lower(). */
    for (size_t i = 0; i < a.len && !a.oom; i++) {
        uint32_t r = a.v[i];
        if (r < 0x80) {
            push(&b, (r >= 'A' && r <= 'Z') ? r + 32 : r);
            continue;
        }
        const char *t = lookup_cp(ks_slug_nfkd, NELEM(ks_slug_nfkd), r);
        push_str(&b, t != NULL ? t : "\x7f");
    }
    if (a.oom || b.oom) {
        free(a.v);
        free(b.v);
        return NULL;
    }
    free(a.v);

    char *out = malloc(b.len + 1);
    if (out == NULL) {
        free(b.v);
        return NULL;
    }
    /* Drop the generated quotes. */
    size_t m = 0;
    for (size_t i = 0; i < b.len; i++) {
        if (b.v[i] != '\'')
            b.v[m++] = b.v[i];
    }
    b.len = m;
    /* Drop the commas between digits (NUMBERS_PATTERN, with lookarounds:
     * "1,2,3" loses both), and turn every run of other characters (what's
     * left of non-ASCII ones is 0x7f) into a single "-". */
    size_t o = 0;
    for (size_t i = 0; i < b.len; i++) {
        uint32_t c = b.v[i];
        if (c == ',' && i > 0 && i + 1 < b.len && is_digit(b.v[i - 1]) && is_digit(b.v[i + 1]))
            continue;
        bool ok = c == '-' || is_digit(c) || (c >= 'a' && c <= 'z');
        char ch = ok ? (char)c : '-';
        if (ch == '-' && o > 0 && out[o - 1] == '-')
            continue;
        out[o++] = ch;
    }
    free(b.v);
    /* strip("-") */
    size_t start = 0;
    while (start < o && out[start] == '-')
        start++;
    while (o > start && out[o - 1] == '-')
        o--;
    memmove(out, out + start, o - start);
    out[o - start] = '\0';
    return out;
}
