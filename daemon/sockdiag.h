/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Socket lookups through netlink sock_diag (NETLINK_SOCK_DIAG). Port of
 * upstream daemon/netlink/socket.go and socket_linux.go (itself based on
 * vishvananda/netlink, Apache-2.0).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: socket arrays are owned by the caller (free()).
 */
#ifndef KS_DAEMON_SOCKDIAG_H
#define KS_DAEMON_SOCKDIAG_H

#include <stddef.h>
#include <stdint.h>

#include "common/netaddr.h"

/* netlink.Socket. Addresses are 16 bytes, as upstream builds them: IPv4 in
 * v4-mapped form. */
struct ks_sock {
    uint8_t family, state, timer, retrans;
    struct ks_ip src, dst;
    uint16_t sport, dport;
    uint32_t iface;
    uint32_t cookie[2];
    uint32_t expires, rqueue, wqueue;
    uint32_t uid;
    uint32_t inode;
};

/* SocketGet: the kernel's sockets of `family`/`proto` (IPPROTO_*) whose
 * source port is `sport` (a dump filtered by port, like upstream).
 * Returns 0, or -1 with `err` filled (also when there's no socket at all,
 * as upstream). */
int ks_sock_get(uint8_t family, uint8_t proto, uint16_t sport,
                struct ks_sock **out, size_t *n, char *err, size_t errlen);

/* SocketsDump: every socket of `family`/`proto`. */
int ks_sock_dump(uint8_t family, uint8_t proto, struct ks_sock **out,
                 size_t *n, char *err, size_t errlen);

/* GetSocketInfo: asks the kernel for the socket of a connection. Sets *uid
 * (-1 if unknown) and up to `max` candidate inodes, most likely first, and
 * returns how many there are. See upstream for the special cases (NTP,
 * broadcasts, incoming connections). */
size_t ks_socket_info(const char *proto, const struct ks_ip *src_ip,
                      unsigned src_port, const struct ks_ip *dst_ip,
                      unsigned dst_port, int64_t *uid, int64_t *inodes,
                      size_t max);

/* GetSocketInfoByInode: searches TCP and UDP, IPv4 and IPv6. 0 if found. */
int ks_sock_find_by_inode(uint32_t inode, struct ks_sock *out);

#endif
