/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Sockets listed in /proc/net/{tcp,tcp6,udp,udp6,udplite,udplite6,raw,raw6}
 * and /proc/net/packet. Port of upstream daemon/netstat/.
 *
 * The lines are parsed with upstream's own (Go) regular expressions, through
 * daemon/rules/regex.c, so odd lines are read exactly as upstream reads them.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: entry arrays returned by the parse functions are owned by the
 * caller (free()); entries hold no pointers.
 */
#ifndef KS_DAEMON_NETSTAT_H
#define KS_DAEMON_NETSTAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/netaddr.h"

/* netstat.Entry */
struct ks_netstat_entry {
    char proto[16];
    struct ks_ip src_ip;
    struct ks_ip dst_ip;
    unsigned src_port;
    unsigned dst_port;
    int64_t iface;
    int64_t uid;   /* UserId (Go int): -1 when unknown */
    int64_t inode; /* INode (Go int): -1 when unknown */
};

/* Parses one data line of /proc/net/<proto> (already trimmed or not).
 * Returns 0, or -1 if the line doesn't match upstream's pattern. */
int ks_netstat_parse_line(const char *proto, const char *line,
                          struct ks_netstat_entry *e);

/* Parse: every entry of `path` (normally /proc/net/<proto>); the first line
 * (column names) is skipped and lines that don't parse are logged and
 * skipped. Returns 0, or -1 if the file can't be read. */
int ks_netstat_parse_file(const char *proto, const char *path,
                          struct ks_netstat_entry **entries, size_t *n);
int ks_netstat_parse(const char *proto, struct ks_netstat_entry **entries,
                     size_t *n);

/* ParsePacket: /proc/net/packet (only iface, uid and inode are filled). */
int ks_netstat_parse_packet_line(const char *line, struct ks_netstat_entry *e);
int ks_netstat_parse_packet(struct ks_netstat_entry **entries, size_t *n);

/* FindEntry: looks the connection up in /proc/net/<proto> and, if IPv6 is
 * enabled and proto has no "6" suffix, in /proc/net/<proto>6. Always fills
 * `out`; uid and inode are -1 if it wasn't found. Returns true if found. */
bool ks_netstat_find(const char *proto, const struct ks_ip *src_ip,
                     unsigned src_port, const struct ks_ip *dst_ip,
                     unsigned dst_port, struct ks_netstat_entry *out);

/* core.IPv6Enabled: /proc/sys/net/ipv6 exists (checked once). */
bool ks_ipv6_enabled(void);

#endif
