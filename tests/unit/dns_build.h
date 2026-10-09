/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Building DNS messages and packets by hand, for the DNS tests. Helpers
 * are inline so each test can use only some of them.
 */
#ifndef KS_TESTS_UNIT_DNS_BUILD_H
#define KS_TESTS_UNIT_DNS_BUILD_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct msg {
    uint8_t b[65536];
    size_t len;
};

static inline void put8(struct msg *m, unsigned v)
{
    if (m->len < sizeof(m->b))
        m->b[m->len++] = (uint8_t)v;
}

static inline void put16(struct msg *m, unsigned v)
{
    put8(m, v >> 8);
    put8(m, v);
}

static inline void put32(struct msg *m, uint32_t v)
{
    put16(m, v >> 16);
    put16(m, v & 0xffff);
}

static inline void put_bytes(struct msg *m, const void *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        put8(m, ((const uint8_t *)p)[i]);
}

/* Header: id 0x1234, flags as given, counts. */
static inline void header(struct msg *m, unsigned flags, unsigned qd, unsigned an,
                          unsigned ns, unsigned ar)
{
    m->len = 0;
    put16(m, 0x1234);
    put16(m, flags);
    put16(m, qd);
    put16(m, an);
    put16(m, ns);
    put16(m, ar);
}

/* A dotted name in label form, root-terminated ("" is just the root). */
static inline void name(struct msg *m, const char *dotted)
{
    while (*dotted) {
        const char *dot = strchr(dotted, '.');
        size_t l = dot ? (size_t)(dot - dotted) : strlen(dotted);
        put8(m, (unsigned)l);
        put_bytes(m, dotted, l);
        dotted += l + (dot ? 1 : 0);
    }
    put8(m, 0);
}

static inline void ptr(struct msg *m, unsigned off)
{
    put16(m, 0xc000 | off);
}

static inline void question(struct msg *m, const char *n, unsigned type)
{
    name(m, n);
    put16(m, type);
    put16(m, 1);
}

/* Record fields after the name: type, class IN, TTL 60, rdlength. */
static inline void rr_head(struct msg *m, unsigned type, unsigned rdlen)
{
    put16(m, type);
    put16(m, 1);
    put32(m, 60);
    put16(m, rdlen);
}

static inline void rr_a(struct msg *m, const char *n, uint8_t a, uint8_t b, uint8_t c,
                        uint8_t d)
{
    name(m, n);
    rr_head(m, 1, 4);
    put8(m, a);
    put8(m, b);
    put8(m, c);
    put8(m, d);
}

static inline void rr_cname(struct msg *m, const char *n, const char *target)
{
    name(m, n);
    size_t at = m->len;
    rr_head(m, 5, 0);
    size_t start = m->len;
    name(m, target);
    size_t rdlen = m->len - start;
    m->b[at + 8] = (uint8_t)(rdlen >> 8);
    m->b[at + 9] = (uint8_t)rdlen;
}

/* A standard response: www.example.com A? -> CNAME cdn.example.net,
 * A 93.184.216.34. */
static inline void sample_response(struct msg *m)
{
    header(m, 0x8180, 1, 2, 0, 0);
    question(m, "www.example.com", 1);
    rr_cname(m, "www.example.com", "cdn.example.net");
    rr_a(m, "cdn.example.net", 93, 184, 216, 34);
}

/* An IPv4/UDP packet carrying `m` from sport to dport (10.0.0.53 ->
 * 10.0.0.2). Returns a malloc'd buffer of exactly *len bytes. */
static inline uint8_t *udp_packet(const struct msg *m, unsigned sport, unsigned dport,
                                  size_t *len)
{
    size_t n = 28 + m->len;
    uint8_t *p = calloc(1, n);
    if (p == NULL)
        abort();
    uint8_t ip[20] = {0x45, 0, (uint8_t)(n >> 8), (uint8_t)n, 0, 1, 0x40, 0, 64, 17, 0, 0,
                      10, 0, 0, 53, 10, 0, 0, 2};
    memcpy(p, ip, 20);
    uint8_t *u = p + 20;
    u[0] = (uint8_t)(sport >> 8);
    u[1] = (uint8_t)sport;
    u[2] = (uint8_t)(dport >> 8);
    u[3] = (uint8_t)dport;
    u[4] = (uint8_t)((8 + m->len) >> 8);
    u[5] = (uint8_t)(8 + m->len);
    memcpy(u + 8, m->b, m->len);
    *len = n;
    return p;
}

#endif
