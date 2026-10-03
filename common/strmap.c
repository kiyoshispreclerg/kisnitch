/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/strmap.h"

#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

void ks_strmap_init(struct ks_strmap *m)
{
    memset(m, 0, sizeof(*m));
    if (getrandom(&m->seed, sizeof(m->seed), GRND_NONBLOCK) != (ssize_t)sizeof(m->seed)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        m->seed = (uint64_t)ts.tv_nsec * 0x9E3779B97F4A7C15ull ^ (uint64_t)(uintptr_t)m;
    }
}

static uint64_t hash(uint64_t seed, const char *s)
{
    uint64_t h = 0xcbf29ce484222325ull ^ seed;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 0x100000001b3ull;
    }
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    return h;
}

static struct ks_strmap_entry **slot(const struct ks_strmap *m, const char *key)
{
    struct ks_strmap_entry **pp = &m->buckets[hash(m->seed, key) & (m->nbuckets - 1)];
    while (*pp != NULL && strcmp((*pp)->key, key) != 0)
        pp = &(*pp)->next;
    return pp;
}

void *ks_strmap_get(const struct ks_strmap *m, const char *key)
{
    if (m->count == 0)
        return NULL;
    struct ks_strmap_entry *e = *slot(m, key);
    return e ? e->value : NULL;
}

static int grow(struct ks_strmap *m)
{
    size_t n = m->nbuckets ? m->nbuckets * 2 : 64;
    struct ks_strmap_entry **b = calloc(n, sizeof(*b));
    if (b == NULL)
        return -1;
    for (size_t i = 0; i < m->nbuckets; i++) {
        struct ks_strmap_entry *e = m->buckets[i];
        while (e != NULL) {
            struct ks_strmap_entry *next = e->next;
            size_t j = hash(m->seed, e->key) & (n - 1);
            e->next = b[j];
            b[j] = e;
            e = next;
        }
    }
    free(m->buckets);
    m->buckets = b;
    m->nbuckets = n;
    return 0;
}

int ks_strmap_set(struct ks_strmap *m, const char *key, void *value, void **old)
{
    if (old != NULL)
        *old = NULL;
    if (m->count + 1 > m->nbuckets && grow(m) < 0)
        return -1;
    struct ks_strmap_entry **pp = slot(m, key);
    if (*pp != NULL) {
        if (old != NULL)
            *old = (*pp)->value;
        (*pp)->value = value;
        return 0;
    }
    struct ks_strmap_entry *e = malloc(sizeof(*e));
    if (e == NULL || (e->key = strdup(key)) == NULL) {
        free(e);
        return -1;
    }
    e->value = value;
    e->next = NULL;
    *pp = e;
    m->count++;
    return 0;
}

void *ks_strmap_del(struct ks_strmap *m, const char *key)
{
    if (m->count == 0)
        return NULL;
    struct ks_strmap_entry **pp = slot(m, key);
    struct ks_strmap_entry *e = *pp;
    if (e == NULL)
        return NULL;
    *pp = e->next;
    void *v = e->value;
    free(e->key);
    free(e);
    m->count--;
    return v;
}

void ks_strmap_filter(struct ks_strmap *m,
                      bool (*fn)(const char *key, void *value, void *ctx),
                      void *ctx)
{
    for (size_t i = 0; i < m->nbuckets; i++) {
        struct ks_strmap_entry **pp = &m->buckets[i];
        while (*pp != NULL) {
            struct ks_strmap_entry *e = *pp;
            if (fn(e->key, e->value, ctx)) {
                *pp = e->next;
                free(e->key);
                free(e);
                m->count--;
            } else {
                pp = &e->next;
            }
        }
    }
}

void ks_strmap_clear(struct ks_strmap *m, void (*free_value)(void *))
{
    for (size_t i = 0; i < m->nbuckets; i++) {
        struct ks_strmap_entry *e = m->buckets[i];
        while (e != NULL) {
            struct ks_strmap_entry *next = e->next;
            if (free_value != NULL)
                free_value(e->value);
            free(e->key);
            free(e);
            e = next;
        }
    }
    free(m->buckets);
    uint64_t seed = m->seed;
    memset(m, 0, sizeof(*m));
    m->seed = seed;
}
