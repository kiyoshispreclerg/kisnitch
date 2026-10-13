/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/arena.h"

#include <stdalign.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 4096

struct ks_arena_block {
    struct ks_arena_block *next;
    size_t used, cap;
    alignas(max_align_t) unsigned char data[];
};

void *ks_arena_alloc(struct ks_arena *a, size_t size)
{
    const size_t align = alignof(max_align_t);
    if (size > SIZE_MAX - align) {
        a->failed = 1;
        return NULL;
    }
    size = (size + align - 1) & ~(align - 1);
    if (size == 0)
        size = align;
    struct ks_arena_block *b = a->head;
    if (b == NULL || b->cap - b->used < size) {
        size_t cap = size > BLOCK_SIZE ? size : BLOCK_SIZE;
        b = malloc(sizeof(*b) + cap);
        if (b == NULL) {
            a->failed = 1;
            return NULL;
        }
        b->used = 0;
        b->cap = cap;
        /* A big one-off block goes behind the current one, which may still
         * have room for small allocations. */
        if (cap > BLOCK_SIZE && a->head != NULL) {
            b->next = a->head->next;
            a->head->next = b;
        } else {
            b->next = a->head;
            a->head = b;
        }
    }
    void *p = b->data + b->used;
    b->used += size;
    memset(p, 0, size);
    return p;
}

void *ks_arena_calloc(struct ks_arena *a, size_t n, size_t size)
{
    if (size != 0 && n > SIZE_MAX / size) {
        a->failed = 1;
        return NULL;
    }
    return ks_arena_alloc(a, n * size);
}

char *ks_arena_strndup(struct ks_arena *a, const char *s, size_t n)
{
    char *d = ks_arena_alloc(a, n + 1);
    if (d != NULL)
        memcpy(d, s, n); /* the terminator is already 0 */
    return d;
}

char *ks_arena_strdup(struct ks_arena *a, const char *s)
{
    return ks_arena_strndup(a, s, strlen(s));
}

char *ks_arena_printf(struct ks_arena *a, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        a->failed = 1;
        return NULL;
    }
    char *d = ks_arena_alloc(a, (size_t)n + 1);
    if (d == NULL)
        return NULL;
    va_start(ap, fmt);
    vsnprintf(d, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return d;
}

void ks_arena_free(struct ks_arena *a)
{
    struct ks_arena_block *b = a->head;
    while (b != NULL) {
        struct ks_arena_block *n = b->next;
        free(b);
        b = n;
    }
    a->head = NULL;
    a->failed = 0;
}
