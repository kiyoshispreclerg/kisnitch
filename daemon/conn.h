/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A connection as seen by the rules engine: the fields of upstream's
 * conman.Connection, procmon.Process and netstat.Entry that operators read.
 * The process monitor (daemon/procmon/) and the packet decoder below fill
 * them in from the system; tests also build them by hand.
 *
 * The packet decoder is a port of the parts of gopacket (v1.1.19, used by
 * upstream) that conman.Parse() reaches: the IPv4/IPv6 layers, IPv6
 * extension headers, IPsec AH, IP-in-IP, and the TCP, UDP, UDP-Lite, SCTP,
 * ICMPv4 and ICMPv6 headers, including how gopacket handles malformed ones.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2012 Google, Inc. (gopacket, BSD-3-Clause)
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: these structs only borrow. Whoever builds a ks_conn keeps the
 * strings, the process and its parents alive while rules are evaluated.
 * struct ks_packet points into the decoded buffer.
 */
#ifndef KS_DAEMON_CONN_H
#define KS_DAEMON_CONN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/netaddr.h"

struct ks_env_var {
    const char *name;
    const char *value;
};

/* procmon.Process (the fields rules use). */
struct ks_process {
    int pid;                        /* ID */
    const char *path;               /* Path */
    const char *const *args;        /* Args */
    size_t nargs;
    const struct ks_env_var *env;   /* Env */
    size_t nenv;
    /* Checksums["process.hash.md5"], Checksums["process.hash.sha1"]:
     * NULL when not computed (absent from the Go map). */
    const char *checksum_md5;
    const char *checksum_sha1;
    const struct ks_process *parent; /* Parent */
};

/* conman.Connection. */
struct ks_conn {
    const char *protocol;  /* Protocol */
    const char *dst_host;  /* DstHost ("" when unknown) */
    struct ks_ip src_ip;   /* SrcIP */
    struct ks_ip dst_ip;   /* DstIP */
    unsigned src_port;     /* SrcPort */
    unsigned dst_port;     /* DstPort */
    int iface_in;          /* Pkt.IfaceInIdx */
    int iface_out;         /* Pkt.IfaceOutIdx */
    long long uid;         /* Entry.UserId (-1: unknown) */
    const struct ks_process *process;
};

/* The transport layer conman.parseDirection() looks for. */
enum ks_l4 {
    KS_L4_NONE,
    KS_L4_TCP,
    KS_L4_UDP,
    KS_L4_UDPLITE,
    KS_L4_SCTP,
    KS_L4_ICMPV4,
    KS_L4_ICMPV6,
};

/* What upstream reads from a queued packet's gopacket layers. */
struct ks_packet {
    /* Packet.IsIPv4(): the first nibble is 4. Anything else is decoded as
     * IPv6, as upstream does. */
    bool ipv4;
    /* The outermost IP layer's SrcIP and DstIP (len 0 when the header was
     * too short to hold them). */
    struct ks_ip src, dst;
    /* The transport layer (none if decoding stopped before one: fragments,
     * malformed or unknown headers, encapsulations not decoded). Ports are
     * 0 for ICMP and for TCP, UDP and SCTP headers too short to hold them,
     * where gopacket still adds the layer. */
    enum ks_l4 l4;
    unsigned sport, dport;
    /* UDP payload (Layer.LayerPayload()), NULL if none. */
    const uint8_t *udp_payload;
    size_t udp_payload_len;
    /* Bytes from udp_payload to the end of the packet buffer: the Go
     * slice's capacity, which some gopacket reads go up to. */
    size_t udp_payload_cap;
};

/* Decodes the IP packet in `data` (as received from nfqueue). Never fails:
 * whatever can't be decoded is left out of `out`. */
void ks_packet_decode(const uint8_t *data, size_t len, struct ks_packet *out);

/* conman.parseDirection(): the connection's protocol ("tcp", "udp6",
 * "udplite", "sctp6", "icmp", "icmp6"...), or NULL if the packet has no
 * transport layer (upstream discards the connection). Static string. */
const char *ks_packet_protocol(const struct ks_packet *p);

/* True if gopacket would decode the UDP payload as DNS: there is a
 * non-empty payload and UDP.NextLayerType() picks LayerTypeDNS (the
 * destination port's layer type if it has one, else the source port's). */
bool ks_packet_udp_next_is_dns(const struct ks_packet *p);

#endif
