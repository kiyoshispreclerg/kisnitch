/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/dns/track.go and daemon/dns/parse.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/dns/cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "common/strmap.h"
#include "common/strset.h"
#include "daemon/dns/parse.h"

/* responses: resolved -> hostname. Entries are also on a list, most
 * recently used first, to drop the oldest one when full. */
struct entry {
    struct entry *prev, *next;
    char *host;
    char key[]; /* the map has its own copy; this one is for eviction */
};

static struct {
    struct ks_strmap map;
    struct entry *head, *tail;
    bool init;
} cache;

/* Names passed to the decoder's visitor: too big for the stack. */
static struct ks_dns_scratch scratch;

static void cache_init(void)
{
    if (!cache.init) {
        ks_strmap_init(&cache.map);
        cache.init = true;
    }
}

static void list_unlink(struct entry *e)
{
    if (e->prev != NULL)
        e->prev->next = e->next;
    else
        cache.head = e->next;
    if (e->next != NULL)
        e->next->prev = e->prev;
    else
        cache.tail = e->prev;
    e->prev = e->next = NULL;
}

static void list_push_front(struct entry *e)
{
    e->prev = NULL;
    e->next = cache.head;
    if (cache.head != NULL)
        cache.head->prev = e;
    cache.head = e;
    if (cache.tail == NULL)
        cache.tail = e;
}

static void entry_free(void *p)
{
    struct entry *e = p;
    free(e->host);
    free(e);
}

void ks_dns_track(const char *resolved, const char *hostname)
{
    if (strncmp(resolved, "127.", 4) == 0)
        return;
    if (strcmp(resolved, "::1") == 0 || strcmp(resolved, hostname) == 0)
        return;

    cache_init();
    struct entry *e = ks_strmap_get(&cache.map, resolved);
    if (e != NULL) {
        char *host = strdup(hostname);
        if (host == NULL)
            return;
        free(e->host);
        e->host = host;
        list_unlink(e);
        list_push_front(e);
    } else {
        size_t klen = strlen(resolved) + 1;
        e = calloc(1, sizeof(*e) + klen);
        if (e != NULL)
            memcpy(e->key, resolved, klen);
        if (e == NULL || (e->host = strdup(hostname)) == NULL ||
            ks_strmap_set(&cache.map, resolved, e, NULL) < 0) {
            if (e != NULL)
                entry_free(e);
            return;
        }
        list_push_front(e);
        if (cache.map.count > KS_DNS_CACHE_MAX) {
            struct entry *old = cache.tail;
            list_unlink(old);
            ks_strmap_del(&cache.map, old->key);
            entry_free(old);
        }
    }
    ks_debug("New DNS record: %s -> %s", resolved, hostname);
}

const char *ks_dns_host(const char *resolved)
{
    if (!cache.init)
        return NULL;
    struct entry *e = ks_strmap_get(&cache.map, resolved);
    if (e == NULL)
        return NULL;
    list_unlink(e);
    list_push_front(e);
    return e->host;
}

char *ks_dns_host_or(const struct ks_ip *ip, const char *or)
{
    char ipstr[KS_IP_STRLEN];
    ks_ip_string(ip, ipstr, sizeof(ipstr));
    const char *host = ks_dns_host(ipstr);
    if (host == NULL)
        return strdup(or);

    /* host might have been CNAME; go back until we reach the "root".
     * `seen` prevents loops. Lookups don't add or drop entries, so the
     * pointers stay valid. */
    struct ks_strset seen;
    ks_strset_init(&seen);
    for (;;) {
        const char *orig = ks_dns_host(host);
        const char *o = orig != NULL ? orig : ""; /* Go's zero value */
        if (ks_strset_has(&seen, o, strlen(o)))
            break;
        if (orig == NULL)
            break;
        if (ks_strset_add(&seen, orig, strlen(orig)) < 0)
            break; /* OOM: stop where we are */
        host = orig;
    }
    char *ret = strdup(host);
    ks_strset_clear(&seen);
    return ret;
}

char *ks_dns_ip_string(const uint8_t *b, size_t len)
{
    if (len == 4 || len == 16) {
        struct ks_ip ip = {.len = (uint8_t)len};
        memcpy(ip.b, b, len);
        char buf[KS_IP_STRLEN];
        ks_ip_string(&ip, buf, sizeof(buf));
        return strdup(buf);
    }
    if (len == 0)
        return strdup("<nil>");
    /* "?" + hexString(ip) */
    char *s = malloc(2 * len + 2);
    if (s == NULL)
        return NULL;
    static const char hex[] = "0123456789abcdef";
    s[0] = '?';
    for (size_t i = 0; i < len; i++) {
        s[1 + 2 * i] = hex[b[i] >> 4];
        s[2 + 2 * i] = hex[b[i] & 0xf];
    }
    s[2 * len + 1] = '\0';
    return s;
}

/* Go strings may hold NUL bytes; ours can't. Such names are left out
 * (docs/UPSTREAM.md, divergences). */
static bool has_nul(const struct ks_dns_name *n)
{
    return memchr(n->s, '\0', n->len) != NULL;
}

static void track_answer(const struct ks_dns_rr *ans, void *ud)
{
    (void)ud;
    if (ans->name.nil || has_nul(&ans->name))
        return;
    if (ans->type == KS_DNS_TYPE_A || ans->type == KS_DNS_TYPE_AAAA) {
        char *ip = ks_dns_ip_string(ans->data, ans->data_len);
        if (ip != NULL)
            ks_dns_track(ip, ans->name.s);
        free(ip);
    } else if (!ans->cname.nil && !has_nul(&ans->cname)) {
        ks_dns_track(ans->cname.s, ans->name.s);
    }
}

bool ks_dns_track_answers(const struct ks_packet *p)
{
    if (p->l4 != KS_L4_UDP || p->sport != 53)
        return false;
    if (!ks_packet_udp_next_is_dns(p))
        return false;
    struct ks_dns_visitor v = {.answer = track_answer};
    return ks_dns_decode(p->udp_payload, p->udp_payload_len, p->udp_payload_cap, NULL, &v,
                         &scratch) == 0;
}

static void last_question(const struct ks_dns_question *q, void *ud)
{
    char **last = ud;
    if (has_nul(&q->name))
        return;
    char *s = strdup(q->name.s);
    if (s == NULL)
        return;
    free(*last);
    *last = s;
}

char *ks_dns_query_domain(const struct ks_packet *p)
{
    if (!ks_packet_udp_next_is_dns(p))
        return NULL;
    char *last = NULL;
    struct ks_dns_visitor v = {.question = last_question, .ud = &last};
    if (ks_dns_decode(p->udp_payload, p->udp_payload_len, p->udp_payload_cap, NULL, &v,
                      &scratch) < 0) {
        free(last); /* can't happen: the visitor only runs on success */
        return NULL;
    }
    return last;
}

size_t ks_dns_cache_count(void)
{
    return cache.init ? cache.map.count : 0;
}

void ks_dns_cache_reset(void)
{
    if (!cache.init)
        return;
    ks_strmap_clear(&cache.map, entry_free);
    cache.head = cache.tail = NULL;
}
