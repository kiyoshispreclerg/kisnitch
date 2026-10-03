/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * IP addresses and networks with the semantics of Go's net package
 * (net.IP, net.ParseIP, net.ParseCIDR, IP.String, IPNet.Contains), which
 * upstream rules depend on (dest.ip, dest.network, network aliases, lists.nets).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#ifndef KS_COMMON_NETADDR_H
#define KS_COMMON_NETADDR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A Go net.IP: `len` is 0 (nil), 4 or 16 bytes. IPv4 may come in either
 * form; 16-byte IPv4 is the v4-mapped ::ffff:a.b.c.d. */
struct ks_ip {
    uint8_t b[16];
    uint8_t len;
};

/* A Go net.IPNet as returned by ParseCIDR: `len` is 4 for IPv4 networks and
 * 16 for IPv6 (including v4-mapped ones); `ip` is already masked. */
struct ks_ipnet {
    uint8_t ip[16];
    uint8_t mask[16];
    uint8_t len;
};

/* Longest IP.String() output plus NUL. */
#define KS_IP_STRLEN 48

/* net.ParseIP: returns 0 and a 16-byte address, or -1 (Go returns nil). */
int ks_ip_parse(const char *s, struct ks_ip *out);

/* Builds an IPv4 address in 4-byte form. */
struct ks_ip ks_ip_v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

/* IP.To4: true and the 4 bytes if `ip` is IPv4 in either form. */
bool ks_ip_to4(const struct ks_ip *ip, uint8_t out[4]);

/* IP.String: "<nil>", dotted IPv4 (also for v4-mapped) or RFC 5952 IPv6. */
void ks_ip_string(const struct ks_ip *ip, char *buf, size_t len);

/* net.IPv4(a, b, c, d): the 16-byte (v4-mapped) form. */
struct ks_ip ks_ip_v4_16(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

/* IP.Equal: an IPv4 address equals its v4-mapped form. */
bool ks_ip_equal(const struct ks_ip *a, const struct ks_ip *b);

/* IP.IsUnspecified, IsLoopback, IsMulticast, IsLinkLocalUnicast and
 * IsGlobalUnicast, as in Go. */
bool ks_ip_is_unspecified(const struct ks_ip *ip);
bool ks_ip_is_loopback(const struct ks_ip *ip);
bool ks_ip_is_multicast(const struct ks_ip *ip);
bool ks_ip_is_link_local_unicast(const struct ks_ip *ip);
bool ks_ip_is_global_unicast(const struct ks_ip *ip);

/* net.ParseCIDR. On error returns -1 and writes Go's message
 * ("invalid CIDR address: <s>") to `err`. */
int ks_parse_cidr(const char *s, struct ks_ipnet *out, char *err, size_t errlen);

/* IPNet.Contains. */
bool ks_ipnet_contains(const struct ks_ipnet *n, const struct ks_ip *ip);

#endif
