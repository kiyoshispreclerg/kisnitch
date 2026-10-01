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
