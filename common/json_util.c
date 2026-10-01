/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/json_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/unicode.h"

char *ks_read_file(const char *path, size_t max_size, size_t *len, char *err,
                   size_t errlen)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return NULL;
    }

    size_t cap = 4096, n = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        snprintf(err, errlen, "read %s: out of memory", path);
        close(fd);
        return NULL;
    }

    for (;;) {
        if (n + 1 >= cap) {
            if (cap > max_size) {
                snprintf(err, errlen, "read %s: file larger than %zu bytes",
                         path, max_size);
                goto fail;
            }
            char *nb = realloc(buf, cap * 2);
            if (nb == NULL) {
                snprintf(err, errlen, "read %s: out of memory", path);
                goto fail;
            }
            buf = nb;
            cap *= 2;
        }
        ssize_t r = read(fd, buf + n, cap - n - 1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            snprintf(err, errlen, "read %s: %s", path, strerror(errno));
            goto fail;
        }
        if (r == 0)
            break;
        n += (size_t)r;
    }
    if (n > max_size) {
        snprintf(err, errlen, "read %s: file larger than %zu bytes", path,
                 max_size);
        goto fail;
    }

    close(fd);
    buf[n] = '\0';
    *len = n;
    return buf;

fail:
    close(fd);
    free(buf);
    return NULL;
}

cJSON *ks_json_parse(const char *buf, size_t len, char *err, size_t errlen)
{
    const char *end = NULL;
    /* cJSON's require_null_terminated wants a NUL inside `len`, so trailing
     * data is checked here instead. */
    cJSON *root = cJSON_ParseWithLengthOpts(buf, len, &end, 0);
    if (root != NULL) {
        size_t pos = (size_t)(end - buf);
        while (pos < len && (buf[pos] == ' ' || buf[pos] == '\t' ||
                             buf[pos] == '\n' || buf[pos] == '\r'))
            pos++;
        if (pos == len)
            return root;
        cJSON_Delete(root);
        end = buf + pos;
    }

    /* cJSON reports where it stopped; turn it into line/column. */
    size_t pos = (end != NULL && end >= buf) ? (size_t)(end - buf) : 0;
    if (pos > len)
        pos = len;
    size_t line = 1, col = 1;
    for (size_t i = 0; i < pos; i++) {
        if (buf[i] == '\n') {
            line++;
            col = 1;
        } else {
            col++;
        }
    }

    if (len == 0 || pos >= len)
        snprintf(err, errlen, "line %zu, column %zu: unexpected end of JSON input",
                 line, col);
    else if ((unsigned char)buf[pos] >= 0x20 && (unsigned char)buf[pos] < 0x7f)
        snprintf(err, errlen, "line %zu, column %zu: invalid JSON near '%c'",
                 line, col, buf[pos]);
    else
        snprintf(err, errlen, "line %zu, column %zu: invalid JSON (byte 0x%02x)",
                 line, col, (unsigned char)buf[pos]);
    return NULL;
}

bool ks_json_equal(const cJSON *a, const cJSON *b)
{
    return cJSON_Compare(a, b, 1);
}

bool ks_json_is_subset(const cJSON *sub, const cJSON *super)
{
    if (sub == NULL || super == NULL)
        return sub == super;

    if (cJSON_IsObject(sub)) {
        if (!cJSON_IsObject(super))
            return false;
        const cJSON *item;
        cJSON_ArrayForEach(item, sub) {
            const cJSON *other = cJSON_GetObjectItemCaseSensitive(super, item->string);
            if (other == NULL || !ks_json_is_subset(item, other))
                return false;
        }
        return true;
    }

    if (cJSON_IsArray(sub)) {
        if (!cJSON_IsArray(super) ||
            cJSON_GetArraySize(sub) != cJSON_GetArraySize(super))
            return false;
        const cJSON *x = sub->child, *y = super->child;
        for (; x != NULL && y != NULL; x = x->next, y = y->next)
            if (!ks_json_is_subset(x, y))
                return false;
        return true;
    }

    return ks_json_equal(sub, super);
}

int ks_write_file(const char *path, const char *data, size_t len, mode_t mode,
                  char *err, size_t errlen)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            snprintf(err, errlen, "write %s: %s", path, strerror(errno));
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    if (close(fd) < 0) {
        snprintf(err, errlen, "close %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

/* ---- Go-compatible serialization -------------------------------------- */

struct sbuf {
    char *p;
    size_t len, cap;
    bool oom;
};

static void sb_put(struct sbuf *b, const char *s, size_t n)
{
    if (b->oom)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (b->len + n + 1 > cap)
            cap *= 2;
        char *np = realloc(b->p, cap);
        if (np == NULL) {
            b->oom = true;
            return;
        }
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void sb_str(struct sbuf *b, const char *s)
{
    sb_put(b, s, strlen(s));
}

/* encoding/json appendString with escapeHTML = true (Go 1.23). */
static void put_go_string(struct sbuf *b, const char *s)
{
    static const char hex[] = "0123456789abcdef";
    size_t n = strlen(s);

    sb_put(b, "\"", 1);
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80) {
            char esc[7];
            switch (c) {
            case '"': sb_put(b, "\\\"", 2); break;
            case '\\': sb_put(b, "\\\\", 2); break;
            case '\b': sb_put(b, "\\b", 2); break;
            case '\f': sb_put(b, "\\f", 2); break;
            case '\n': sb_put(b, "\\n", 2); break;
            case '\r': sb_put(b, "\\r", 2); break;
            case '\t': sb_put(b, "\\t", 2); break;
            default:
                if (c < 0x20 || c == '<' || c == '>' || c == '&') {
                    esc[0] = '\\'; esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
                    esc[4] = hex[c >> 4]; esc[5] = hex[c & 0xF];
                    sb_put(b, esc, 6);
                } else {
                    sb_put(b, s + i, 1);
                }
            }
            i++;
            continue;
        }
        uint32_t r;
        size_t w = ks_utf8_decode(s + i, n - i, &r);
        if (r == KS_RUNE_ERROR && w == 1)
            sb_str(b, "\\ufffd");
        else if (r == 0x2028)
            sb_str(b, "\\u2028");
        else if (r == 0x2029)
            sb_str(b, "\\u2029");
        else
            sb_put(b, s + i, w);
        i += w;
    }
    sb_put(b, "\"", 1);
}

static void put_go_number(struct sbuf *b, double d)
{
    char num[40];
    if (d == (double)(long long)d && d > -9.2e18 && d < 9.2e18)
        snprintf(num, sizeof(num), "%lld", (long long)d);
    else
        snprintf(num, sizeof(num), "%.17g", d);
    sb_str(b, num);
}

static void put_indent(struct sbuf *b, bool indent, int depth)
{
    if (!indent)
        return;
    sb_put(b, "\n", 1);
    for (int i = 0; i < depth; i++)
        sb_put(b, "  ", 2);
}

static void put_go_value(struct sbuf *b, const cJSON *v, bool indent, int depth)
{
    if (cJSON_IsNull(v) || cJSON_IsInvalid(v)) {
        sb_str(b, "null");
    } else if (cJSON_IsFalse(v)) {
        sb_str(b, "false");
    } else if (cJSON_IsTrue(v)) {
        sb_str(b, "true");
    } else if (cJSON_IsNumber(v)) {
        put_go_number(b, v->valuedouble);
    } else if (cJSON_IsString(v)) {
        put_go_string(b, v->valuestring);
    } else if (cJSON_IsArray(v) || cJSON_IsObject(v)) {
        bool obj = cJSON_IsObject(v);
        sb_put(b, obj ? "{" : "[", 1);
        /* json.Indent leaves empty arrays and objects on one line. */
        if (v->child != NULL) {
            for (const cJSON *c = v->child; c != NULL; c = c->next) {
                put_indent(b, indent, depth + 1);
                if (obj) {
                    put_go_string(b, c->string != NULL ? c->string : "");
                    sb_str(b, indent ? ": " : ":");
                }
                put_go_value(b, c, indent, depth + 1);
                if (c->next != NULL)
                    sb_put(b, ",", 1);
            }
            put_indent(b, indent, depth);
        }
        sb_put(b, obj ? "}" : "]", 1);
    }
}

char *ks_json_print_go(const cJSON *v, bool indent)
{
    struct sbuf b = {0};
    put_go_value(&b, v, indent, 0);
    if (b.oom) {
        free(b.p);
        return NULL;
    }
    return b.p;
}
