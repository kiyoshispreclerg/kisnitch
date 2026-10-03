/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/netstat/.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/netstat.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/json_util.h"
#include "common/log.h"
#include "daemon/rules/regex.h"

#define PROC_NET_MAX_SIZE (64u * 1024 * 1024)

/* Verbatim from upstream's parse.go and parse_packet.go. */
static const char line_pattern[] =
    "(?i)"
    "\\d+:\\s+"                                  /* sl */
    "([a-f0-9]{8,32}):([a-f0-9]{4})\\s+"        /* local_address */
    "([a-f0-9]{8,32}):([a-f0-9]{4})\\s+"        /* rem_address */
    "[a-f0-9]{2}\\s+"                            /* st */
    "[a-f0-9]{8}:[a-f0-9]{8}\\s+"                /* tx_queue rx_queue */
    "[a-f0-9]{2}:[a-f0-9]{8}\\s+"                /* tr tm->when */
    "[a-f0-9]{8}\\s+"                            /* retrnsmt */
    "(\\d+)\\s+"                                 /* uid */
    "\\d+\\s+"                                   /* timeout */
    "(\\d+)\\s+"                                 /* inode */
    ".+";                                        /* stuff we don't care about */

static const char packet_pattern[] =
    "(?i)"
    "[a-z0-9]+\\s+"   /* sk */
    "[0-9]\\s+"       /* refCnt */
    "([0-9])\\s+"     /* Type */
    "([0-9a-z]+)\\s+" /* proto */
    "([0-9])\\s+"     /* iface */
    "[0-9]\\s+"       /* r */
    "[0-9]+\\s+"      /* rmem */
    "([0-9]+)\\s+"    /* user */
    "([0-9]+)";       /* inode */

static pthread_once_t once = PTHREAD_ONCE_INIT;
static struct ks_regex *line_re, *packet_re;
static bool ipv6_enabled;

static void init(void)
{
    char err[256];
    line_re = ks_regex_compile_flags(line_pattern, KS_REGEX_CAPTURE, err, sizeof(err));
    packet_re = ks_regex_compile_flags(packet_pattern, KS_REGEX_CAPTURE, err, sizeof(err));
    if (line_re == NULL || packet_re == NULL)
        ks_fatal("netstat: %s", err);
    struct stat st;
    ipv6_enabled = stat("/proc/sys/net/ipv6", &st) == 0;
}

bool ks_ipv6_enabled(void)
{
    pthread_once(&once, init);
    return ipv6_enabled;
}

/* strconv.ParseUint(s[a:b], 16, 64). */
static int parse_hex(const char *s, long a, long b, uint64_t *out)
{
    uint64_t v = 0;
    if (b <= a || b - a > 16)
        return -1;
    for (long i = a; i < b; i++) {
        char c = s[i];
        int d = c >= '0' && c <= '9' ? c - '0'
              : c >= 'a' && c <= 'f' ? c - 'a' + 10
              : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0)
            return -1;
        v = v << 4 | (uint64_t)d;
    }
    *out = v;
    return 0;
}

/* strconv.ParseInt(s[a:b], 10, 64). Upstream exits on overflow
 * (log.Fatal); here the line is rejected instead. */
static int parse_dec(const char *s, long a, long b, int64_t *out)
{
    int64_t v = 0;
    for (long i = a; i < b; i++) {
        int d = s[i] - '0';
        if (v > (INT64_MAX - d) / 10)
            return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* hexToIP. Upstream stores each 32-bit word little-endian (the kernel prints
 * them in host order), and decides between IPv4 and IPv6 by whether the low
 * 64 bits are zero, so an IPv6 address whose last 64 bits are 0 comes out as
 * a 4-byte address (reproduced; see docs/UPSTREAM.md). */
static int hex_to_ip(const char *s, long a, long b, struct ks_ip *ip)
{
    uint64_t n, m = 0;
    if (b - a > 16) {
        if (parse_hex(s, a, a + 16, &n) < 0 || parse_hex(s, a + 16, b, &m) < 0)
            return -1;
    } else if (parse_hex(s, a, b, &n) < 0) {
        return -1;
    }
    memset(ip, 0, sizeof(*ip));
    if (m != 0) {
        put_le32(ip->b, (uint32_t)(n >> 32));
        put_le32(ip->b + 4, (uint32_t)n);
        put_le32(ip->b + 8, (uint32_t)(m >> 32));
        put_le32(ip->b + 12, (uint32_t)m);
        ip->len = 16;
    } else {
        put_le32(ip->b, (uint32_t)n);
        ip->len = 4;
    }
    return 0;
}

/* core.Trim */
static void trim(const char **s, size_t *n)
{
    while (*n > 0 && strchr("\r\n\t ", (*s)[0]) && (*s)[0] != '\0') {
        (*s)++;
        (*n)--;
    }
    while (*n > 0 && strchr("\r\n\t ", (*s)[*n - 1]) && (*s)[*n - 1] != '\0')
        (*n)--;
}

static int parse_span(const char *proto, const char *line, size_t len,
                      struct ks_netstat_entry *e)
{
    long g[14];
    pthread_once(&once, init);
    trim(&line, &len);
    if (ks_regex_find_submatch(line_re, line, len, g, 7) != 7)
        return -1;

    uint64_t sport, dport;
    memset(e, 0, sizeof(*e));
    snprintf(e->proto, sizeof(e->proto), "%s", proto);
    if (hex_to_ip(line, g[2], g[3], &e->src_ip) < 0 ||
        parse_hex(line, g[4], g[5], &sport) < 0 ||
        hex_to_ip(line, g[6], g[7], &e->dst_ip) < 0 ||
        parse_hex(line, g[8], g[9], &dport) < 0 ||
        parse_dec(line, g[10], g[11], &e->uid) < 0 ||
        parse_dec(line, g[12], g[13], &e->inode) < 0)
        return -1;
    e->src_port = (unsigned)sport;
    e->dst_port = (unsigned)dport;
    return 0;
}

int ks_netstat_parse_line(const char *proto, const char *line,
                          struct ks_netstat_entry *e)
{
    return parse_span(proto, line, strlen(line), e);
}

static int packet_span(const char *line, size_t len, struct ks_netstat_entry *e)
{
    long g[12];
    pthread_once(&once, init);
    trim(&line, &len);
    if (ks_regex_find_submatch(packet_re, line, len, g, 6) != 6)
        return -1;
    memset(e, 0, sizeof(*e));
    if (parse_dec(line, g[6], g[7], &e->iface) < 0 ||
        parse_dec(line, g[8], g[9], &e->uid) < 0 ||
        parse_dec(line, g[10], g[11], &e->inode) < 0)
        return -1;
    return 0;
}

int ks_netstat_parse_packet_line(const char *line, struct ks_netstat_entry *e)
{
    return packet_span(line, strlen(line), e);
}

/* Reads `path` and parses every line but the first with `fn`. */
static int parse_lines(const char *proto, const char *path,
                       int (*fn)(const char *, const char *, size_t,
                                 struct ks_netstat_entry *),
                       struct ks_netstat_entry **entries, size_t *n)
{
    char err[256];
    size_t len;
    *entries = NULL;
    *n = 0;
    char *raw = ks_read_file(path, PROC_NET_MAX_SIZE, &len, err, sizeof(err));
    if (raw == NULL) {
        ks_debug("netstat: %s", err);
        return -1;
    }

    size_t cap = 0;
    const char *p = raw, *end = raw + len;
    for (int lineno = 0; p < end; lineno++) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t l = nl ? (size_t)(nl - p) : (size_t)(end - p);
        const char *line = p;
        p = nl ? nl + 1 : end;
        if (lineno == 0) /* column names */
            continue;

        struct ks_netstat_entry e;
        if (fn(proto, line, l, &e) < 0) {
            ks_warning("Could not parse netstat line from %s: %.*s", path, (int)l, line);
            continue;
        }
        if (*n == cap) {
            cap = cap ? cap * 2 : 64;
            struct ks_netstat_entry *ne = realloc(*entries, cap * sizeof(*ne));
            if (ne == NULL)
                break;
            *entries = ne;
        }
        (*entries)[(*n)++] = e;
    }
    free(raw);
    return 0;
}

int ks_netstat_parse_file(const char *proto, const char *path,
                          struct ks_netstat_entry **entries, size_t *n)
{
    return parse_lines(proto, path, parse_span, entries, n);
}

int ks_netstat_parse(const char *proto, struct ks_netstat_entry **entries,
                     size_t *n)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/net/%s", proto);
    return ks_netstat_parse_file(proto, path, entries, n);
}

static int packet_fn(const char *proto, const char *line, size_t len,
                     struct ks_netstat_entry *e)
{
    (void)proto;
    return packet_span(line, len, e);
}

int ks_netstat_parse_packet(struct ks_netstat_entry **entries, size_t *n)
{
    return parse_lines("", "/proc/net/packet", packet_fn, entries, n);
}

/* findEntryForProtocol */
static bool find_for_protocol(const char *proto, const struct ks_ip *src_ip,
                              unsigned src_port, const struct ks_ip *dst_ip,
                              unsigned dst_port, struct ks_netstat_entry *out)
{
    struct ks_netstat_entry *entries;
    size_t n;
    if (ks_netstat_parse(proto, &entries, &n) < 0) {
        ks_warning("Error while searching for %s netstat entry: %s", proto,
                   strerror(errno));
        return false;
    }
    bool found = false;
    for (size_t i = 0; i < n && !found; i++) {
        const struct ks_netstat_entry *e = &entries[i];
        if (ks_ip_equal(src_ip, &e->src_ip) && src_port == e->src_port &&
            ks_ip_equal(dst_ip, &e->dst_ip) && dst_port == e->dst_port) {
            *out = *e;
            found = true;
        }
    }
    free(entries);
    return found;
}

bool ks_netstat_find(const char *proto, const struct ks_ip *src_ip,
                     unsigned src_port, const struct ks_ip *dst_ip,
                     unsigned dst_port, struct ks_netstat_entry *out)
{
    if (find_for_protocol(proto, src_ip, src_port, dst_ip, dst_port, out))
        return true;

    size_t len = strlen(proto);
    if (ks_ipv6_enabled() && (len == 0 || proto[len - 1] != '6')) {
        char other[24];
        snprintf(other, sizeof(other), "%s6", proto);
        ks_debug("Searching for %s netstat entry instead of %s", other, proto);
        if (find_for_protocol(other, src_ip, src_port, dst_ip, dst_port, out))
            return true;
    }

    memset(out, 0, sizeof(*out));
    snprintf(out->proto, sizeof(out->proto), "%s", proto);
    out->src_ip = *src_ip;
    out->src_port = src_port;
    out->dst_ip = *dst_ip;
    out->dst_port = dst_port;
    out->uid = -1;
    out->inode = -1;
    return false;
}
