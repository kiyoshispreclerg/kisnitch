/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Python's json.dumps() (Lib/json/encoder.py) with default arguments.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/pyjson.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/unicode.h"

void ks_pybuf_add(struct ks_pybuf *b, const char *s, size_t n)
{
    if (b->oom)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t ncap = b->cap ? b->cap : 64;
        while (ncap < b->len + n + 1)
            ncap *= 2;
        char *ns = realloc(b->s, ncap);
        if (ns == NULL) {
            b->oom = true;
            return;
        }
        b->s = ns;
        b->cap = ncap;
    }
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = '\0';
}

void ks_pybuf_adds(struct ks_pybuf *b, const char *s)
{
    ks_pybuf_add(b, s, strlen(s));
}

char *ks_pybuf_finish(struct ks_pybuf *b)
{
    if (b->oom) {
        free(b->s);
        b->s = NULL;
        return NULL;
    }
    if (b->s == NULL)
        ks_pybuf_add(b, "", 0);
    return b->s;
}

static void add_u(struct ks_pybuf *b, unsigned v)
{
    char tmp[8];
    snprintf(tmp, sizeof(tmp), "\\u%04x", v);
    ks_pybuf_adds(b, tmp);
}

/* py_encode_basestring_ascii */
void ks_pybuf_add_json_str(struct ks_pybuf *b, const char *s)
{
    size_t n = strlen(s);
    ks_pybuf_add(b, "\"", 1);
    for (size_t i = 0; i < n;) {
        uint32_t r;
        size_t l = ks_utf8_decode(s + i, n - i, &r);
        i += l ? l : 1;
        switch (r) {
        case '"': ks_pybuf_adds(b, "\\\""); continue;
        case '\\': ks_pybuf_adds(b, "\\\\"); continue;
        case '\n': ks_pybuf_adds(b, "\\n"); continue;
        case '\r': ks_pybuf_adds(b, "\\r"); continue;
        case '\t': ks_pybuf_adds(b, "\\t"); continue;
        case '\b': ks_pybuf_adds(b, "\\b"); continue;
        case '\f': ks_pybuf_adds(b, "\\f"); continue;
        default: break;
        }
        if (r >= 0x20 && r < 0x7f) {
            char c = (char)r;
            ks_pybuf_add(b, &c, 1);
        } else if (r == 0x7f) {
            ks_pybuf_add(b, "\x7f", 1);
        } else if (r > 0xFFFF) {
            r -= 0x10000;
            add_u(b, 0xD800 | ((r >> 10) & 0x3FF));
            add_u(b, 0xDC00 | (r & 0x3FF));
        } else {
            add_u(b, r);
        }
    }
    ks_pybuf_add(b, "\"", 1);
}

/* float.__repr__: the shortest string that reads back as the same double;
 * "1e-05" and "1e+16" style exponents, as C's %g writes them. */
static void add_number(struct ks_pybuf *b, double d)
{
    char tmp[40];
    if (isnan(d)) {
        ks_pybuf_adds(b, "NaN");
        return;
    }
    if (isinf(d)) {
        ks_pybuf_adds(b, d > 0 ? "Infinity" : "-Infinity");
        return;
    }
    if (d == floor(d) && fabs(d) < 1e16) {
        snprintf(tmp, sizeof(tmp), "%.0f", d);
        if (strcmp(tmp, "-0") == 0)
            snprintf(tmp, sizeof(tmp), "0");
        ks_pybuf_adds(b, tmp);
        return;
    }
    for (int p = 1; p <= 17; p++) {
        snprintf(tmp, sizeof(tmp), "%.*g", p, d);
        if (strtod(tmp, NULL) == d)
            break;
    }
    if (strpbrk(tmp, ".en") == NULL)
        snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), ".0");
    ks_pybuf_adds(b, tmp);
}

static void newline(struct ks_pybuf *b, int indent, int level)
{
    ks_pybuf_adds(b, "\n");
    for (int i = 0; i < indent * level; i++)
        ks_pybuf_adds(b, " ");
}

/* indent < 0: json.dumps(v); otherwise json.dumps(v, indent=" " * indent),
 * whose item separator is "," at the end of a line. */
static void dump(struct ks_pybuf *b, const cJSON *v, int indent, int level)
{
    if (cJSON_IsNull(v)) {
        ks_pybuf_adds(b, "null");
    } else if (cJSON_IsTrue(v)) {
        ks_pybuf_adds(b, "true");
    } else if (cJSON_IsFalse(v)) {
        ks_pybuf_adds(b, "false");
    } else if (cJSON_IsNumber(v)) {
        add_number(b, v->valuedouble);
    } else if (cJSON_IsString(v)) {
        ks_pybuf_add_json_str(b, v->valuestring);
    } else if (cJSON_IsArray(v) || cJSON_IsObject(v)) {
        bool obj = cJSON_IsObject(v);
        ks_pybuf_adds(b, obj ? "{" : "[");
        for (const cJSON *c = v->child; c != NULL; c = c->next) {
            if (indent >= 0)
                newline(b, indent, level + 1);
            if (obj) {
                ks_pybuf_add_json_str(b, c->string);
                ks_pybuf_adds(b, ": ");
            }
            dump(b, c, indent, level + 1);
            if (c->next != NULL)
                ks_pybuf_adds(b, indent >= 0 ? "," : ", ");
        }
        if (indent >= 0 && v->child != NULL)
            newline(b, indent, level);
        ks_pybuf_adds(b, obj ? "}" : "]");
    } else {
        ks_pybuf_adds(b, "null");
    }
}

char *ks_pyjson_dumps(const cJSON *v)
{
    struct ks_pybuf b = {0};
    dump(&b, v, -1, 0);
    return ks_pybuf_finish(&b);
}

char *ks_pyjson_dumps_indent(const cJSON *v, int indent)
{
    struct ks_pybuf b = {0};
    dump(&b, v, indent, 0);
    return ks_pybuf_finish(&b);
}
