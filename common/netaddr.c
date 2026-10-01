/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Address parsing follows netip.ParseAddr from Go 1.23 (src/net/netip),
 * Copyright 2020 The Go Authors (BSD-3-Clause).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/netaddr.h"

#include <stdio.h>
#include <string.h>

static const uint8_t v4_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

/* netip parseIPv4: four decimal fields, no leading zeros, each <= 255. */
static int parse_v4(const char *s, size_t n, uint8_t out[4])
{
    int field = 0, val = 0, digits = 0;

    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            if (digits == 1 && val == 0) /* leading zero */
                return -1;
            val = val * 10 + (c - '0');
            if (val > 255)
                return -1;
            digits++;
        } else if (c == '.') {
            if (digits == 0 || field == 3)
                return -1;
            out[field++] = (uint8_t)val;
            val = 0;
            digits = 0;
        } else {
            return -1;
        }
    }
    if (field != 3 || digits == 0)
        return -1;
    out[3] = (uint8_t)val;
    return 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* netip parseIPv6 (without zone). */
static int parse_v6(const char *s, size_t n, uint8_t ip[16])
{
    int ellipsis = -1; /* position of "::" in bytes */
    size_t i = 0;      /* bytes filled */
    size_t p = 0;

    memset(ip, 0, 16);
    if (n >= 2 && s[0] == ':' && s[1] == ':') {
        ellipsis = 0;
        p = 2;
        if (p == n) /* "::" */
            return 0;
    }

    while (i < 16) {
        /* Hex number (at most 4 digits). */
        size_t off = 0;
        unsigned acc = 0;
        while (p + off < n) {
            int h = hexval(s[p + off]);
            if (h < 0)
                break;
            if (off == 4) /* more than 4 digits */
                return -1;
            acc = (acc << 4) | (unsigned)h;
            off++;
        }
        if (off == 0) /* no digits */
            return -1;

        /* An IPv4 tail? */
        if (p + off < n && s[p + off] == '.') {
            if (ellipsis < 0 && i != 12) /* not the right place */
                return -1;
            if (i + 4 > 16)
                return -1;
            if (parse_v4(s + p, n - p, ip + i) < 0)
                return -1;
            p = n;
            i += 4;
            break;
        }

        ip[i] = (uint8_t)(acc >> 8);
        ip[i + 1] = (uint8_t)acc;
        i += 2;
        p += off;

        if (p == n)
            break;
        if (s[p] != ':' || p + 1 == n) /* trailing colon */
            return -1;
        p++;

        if (s[p] == ':') {
            if (ellipsis >= 0) /* already have one */
                return -1;
            ellipsis = (int)i;
            p++;
            if (p == n) /* can be at end */
                break;
        }
    }

    if (p != n) /* trailing garbage */
        return -1;

    if (i < 16) {
        if (ellipsis < 0)
            return -1;
        size_t gap = 16 - i;
        for (int j = (int)i - 1; j >= ellipsis; j--)
            ip[j + gap] = ip[j];
        memset(ip + ellipsis, 0, gap);
    } else if (ellipsis >= 0) {
        /* Ellipsis must represent at least one 0 group. */
        return -1;
    }
    return 0;
}

/* netip.ParseAddr. Returns 4 or 16 (the address family), or -1. Zones are
 * rejected, since every caller here (ParseIP, ParseCIDR) rejects them. */
static int parse_addr(const char *s, size_t n, uint8_t ip[16])
{
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '.') {
            if (parse_v4(s, n, ip + 12) < 0)
                return -1;
            memcpy(ip, v4_prefix, 12);
            return 4;
        }
        if (s[i] == ':' || s[i] == '%') {
            for (size_t j = 0; j < n; j++)
                if (s[j] == '%')
                    return -1;
            return parse_v6(s, n, ip) < 0 ? -1 : 16;
        }
    }
    return -1;
}

int ks_ip_parse(const char *s, struct ks_ip *out)
{
    memset(out, 0, sizeof(*out));
    if (parse_addr(s, strlen(s), out->b) < 0)
        return -1;
    out->len = 16;
    return 0;
}

struct ks_ip ks_ip_v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    struct ks_ip ip = {{a, b, c, d}, 4};
    return ip;
}

bool ks_ip_to4(const struct ks_ip *ip, uint8_t out[4])
{
    if (ip->len == 4) {
        memcpy(out, ip->b, 4);
        return true;
    }
    if (ip->len == 16 && memcmp(ip->b, v4_prefix, 12) == 0) {
        memcpy(out, ip->b + 12, 4);
        return true;
    }
    return false;
}

void ks_ip_string(const struct ks_ip *ip, char *buf, size_t len)
{
    uint8_t v4[4];

    if (ip->len == 0) {
        snprintf(buf, len, "<nil>");
        return;
    }
    if (ks_ip_to4(ip, v4)) {
        snprintf(buf, len, "%u.%u.%u.%u", v4[0], v4[1], v4[2], v4[3]);
        return;
    }

    /* RFC 5952: the longest run of two or more zero groups (the first one on
     * ties) becomes "::"; hex digits are lowercase without leading zeros. */
    uint16_t g[8];
    for (int i = 0; i < 8; i++)
        g[i] = (uint16_t)(ip->b[2 * i] << 8 | ip->b[2 * i + 1]);
    int best = -1, best_len = 0;
    for (int i = 0; i < 8;) {
        if (g[i] != 0) {
            i++;
            continue;
        }
        int j = i;
        while (j < 8 && g[j] == 0)
            j++;
        if (j - i > best_len && j - i >= 2) {
            best = i;
            best_len = j - i;
        }
        i = j;
    }

    size_t o = 0;
    buf[0] = '\0';
    for (int i = 0; i < 8; i++) {
        if (i == best) {
            o += (size_t)snprintf(buf + o, o < len ? len - o : 0, "::");
            i += best_len - 1;
            continue;
        }
        if (i > 0 && i != best + best_len)
            o += (size_t)snprintf(buf + o, o < len ? len - o : 0, ":");
        o += (size_t)snprintf(buf + o, o < len ? len - o : 0, "%x", g[i]);
    }
}

int ks_parse_cidr(const char *s, struct ks_ipnet *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    const char *slash = strchr(s, '/');
    uint8_t ip[16];
    int family;

    if (slash == NULL ||
        (family = parse_addr(s, (size_t)(slash - s), ip)) < 0)
        goto fail;

    /* dtoi: decimal digits only, at least one. */
    const char *m = slash + 1;
    long bits = 0;
    size_t nd = 0;
    for (; m[nd] >= '0' && m[nd] <= '9'; nd++) {
        bits = bits * 10 + (m[nd] - '0');
        if (bits >= 0xFFFFFF)
            goto fail;
    }
    if (nd == 0 || m[nd] != '\0' || bits > family * 8)
        goto fail;

    out->len = (uint8_t)family;
    const uint8_t *src = family == 4 ? ip + 12 : ip;
    for (int i = 0; i < family; i++) {
        long b = bits - i * 8;
        uint8_t mask = b >= 8 ? 0xff : b <= 0 ? 0 : (uint8_t)(0xff << (8 - b));
        out->mask[i] = mask;
        out->ip[i] = src[i] & mask;
    }
    return 0;

fail:
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, "invalid CIDR address: %s", s);
    return -1;
}

bool ks_ipnet_contains(const struct ks_ipnet *n, const struct ks_ip *ip)
{
    /* networkNumberAndMask */
    const uint8_t *nn, *m;
    size_t l;
    if (n->len == 4) {
        nn = n->ip;
        m = n->mask;
        l = 4;
    } else if (n->len == 16 && memcmp(n->ip, v4_prefix, 12) == 0) {
        nn = n->ip + 12; /* v4-mapped network: last 4 bytes of the mask */
        m = n->mask + 12;
        l = 4;
    } else if (n->len == 16) {
        nn = n->ip;
        m = n->mask;
        l = 16;
    } else {
        return false;
    }

    uint8_t v4[4];
    const uint8_t *x;
    size_t xl;
    if (ks_ip_to4(ip, v4)) {
        x = v4;
        xl = 4;
    } else {
        x = ip->b;
        xl = ip->len;
    }
    if (xl != l)
        return false;
    for (size_t i = 0; i < l; i++)
        if ((nn[i] & m[i]) != (x[i] & m[i]))
            return false;
    return true;
}
