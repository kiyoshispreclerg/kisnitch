/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Resolved names: which hostname an IP (or a CNAME target) came from, so
 * that rules on dest.host work. Port of upstream daemon/dns/track.go
 * (TrackAnswers, Track, Host, HostOr) and daemon/dns/parse.go
 * (GetQuestions).
 *
 * The cache is fed from DNS responses seen on the netfilter queue (any
 * resolver: the queue gets every UDP packet from port 53, loopback
 * included) and, when systemd-resolved is running, from its monitor
 * (daemon/dns/resolved.c).
 *
 * Upstream's map never shrinks; this one keeps the KS_DNS_CACHE_MAX most
 * recently used entries (docs/UPSTREAM.md, divergences).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the cache owns copies of its keys and values. All state is
 * global, like upstream's; single-threaded.
 */
#ifndef KS_DAEMON_DNS_CACHE_H
#define KS_DAEMON_DNS_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/netaddr.h"
#include "daemon/conn.h"

/* About 2 MB when full of long names (docs/BENCH.md). */
#define KS_DNS_CACHE_MAX 8192

/* dns.Track: remembers that `resolved` (an IP string or a CNAME target)
 * came from `hostname`. Loopback answers and self-references are skipped. */
void ks_dns_track(const char *resolved, const char *hostname);

/* dns.Host: the hostname `resolved` came from, or NULL. The pointer is
 * valid until the next ks_dns_track() or ks_dns_cache_reset(). */
const char *ks_dns_host(const char *resolved);

/* dns.HostOr: the name `ip` was resolved from, following CNAMEs back to
 * the name that was asked for, or `or` if unknown. Returns a malloc'd
 * copy (NULL on OOM). */
char *ks_dns_host_or(const struct ks_ip *ip, const char *or);

/* dns.TrackAnswers: if `p` is a UDP packet from port 53 that gopacket
 * decodes as DNS, tracks its answers (A/AAAA addresses and CNAMEs) and
 * returns true: the packet is accepted without further checks. */
bool ks_dns_track_answers(const struct ks_packet *p);

/* conman getDomains() with dns.GetQuestions(): for a UDP packet that
 * decodes as DNS, the name of its last question, malloc'd; NULL if there
 * is none (or on OOM). */
char *ks_dns_query_domain(const struct ks_packet *p);

/* net.IP(b).String() for any length: "<nil>", dotted IPv4, IPv6, or "?"
 * followed by the bytes in hex. Returns a malloc'd string (NULL on OOM). */
char *ks_dns_ip_string(const uint8_t *b, size_t len);

/* For tests: number of entries, and dropping all of them. */
size_t ks_dns_cache_count(void);
void ks_dns_cache_reset(void);

#endif
