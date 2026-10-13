/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Packet decoding for conman.Parse(). Port of the gopacket v1.1.19 decoders
 * upstream's conman/connection.go reaches through packet.Layer() (layers/
 * ip4.go, ip6.go, ipsec.go, tcp.go, udp.go, udplite.go, sctp.go, icmp4.go,
 * icmp6.go; lazy decoding from packet.go) and of parseDirection().
 *
 * gopacket decodes one layer at a time. A decoder that fails may still have
 * added its layer (with whatever fields it set before failing); either way
 * decoding stops there. Decoding also stops when a layer has no payload.
 * The comments say which case each check follows.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2012 Google, Inc. (gopacket, BSD-3-Clause)
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/conn.h"

#include <stdio.h>
#include <string.h>

/* IPProtocol values gopacket has decoders for that can lead to a
 * transport layer (layers/enums.go). */
enum {
    PROTO_HOPOPTS = 0,
    PROTO_ICMPV4 = 1,
    PROTO_IPV4 = 4,
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_IPV6 = 41,
    PROTO_ROUTING = 43,
    PROTO_FRAGMENT = 44,
    PROTO_AH = 51,
    PROTO_ICMPV6 = 58,
    PROTO_DSTOPTS = 60,
    PROTO_IPIP = 94,
    PROTO_SCTP = 132,
    PROTO_UDPLITE = 136,
};

#define IPV6_HOPOPT_JUMBO 0xc2
#define IPV6_MAX_PAYLOAD 65535

/* What decoding one layer leads to. */
enum next_kind { NEXT_STOP, NEXT_IPV4, NEXT_IPV6, NEXT_PROTO };

struct cursor {
    const uint8_t *data;
    size_t len;
    enum next_kind next;
    uint8_t proto; /* for NEXT_PROTO */
};

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void set_ip(struct ks_ip *ip, const uint8_t *b, uint8_t len)
{
    memcpy(ip->b, b, len);
    ip->len = len;
}

/* The next layer is decoded from `data`; an empty payload ends decoding
 * (lazyPacket.decodeNextLayer). */
static void next_layer(struct cursor *c, enum next_kind kind, uint8_t proto,
                       const uint8_t *data, size_t len)
{
    c->data = data;
    c->len = len;
    c->next = len == 0 ? NEXT_STOP : kind;
    c->proto = proto;
}

/* IPProtocol.LayerType() as a decoder. */
static void next_proto(struct cursor *c, uint8_t proto, const uint8_t *data,
                       size_t len)
{
    next_layer(c, NEXT_PROTO, proto, data, len);
}

/* decodeIPv4 / IPv4.DecodeFromBytes. */
static void decode_ipv4(struct cursor *c, struct ks_packet *out, bool outer)
{
    const uint8_t *data = c->data;
    size_t len = c->len;
    c->next = NEXT_STOP;
    if (len < 20)
        return; /* layer added without addresses */

    if (outer) {
        set_ip(&out->src, data + 12, 4);
        set_ip(&out->dst, data + 16, 4);
    }
    uint16_t flagsfrags = be16(data + 6);
    unsigned ihl = data[0] & 0x0f;
    size_t length = be16(data + 2);
    if (length == 0) /* TSO: the length is the data's */
        length = (uint16_t)len;
    if (length < 20 || ihl < 5 || ihl * 4 > length)
        return;
    if (len > length)
        len = length;
    else if (len < length && ihl * 4 > len)
        return; /* "Not all IP header bytes available" */

    /* Options */
    const uint8_t *opt = data + 20;
    size_t optlen = ihl * 4 - 20;
    while (optlen > 0) {
        if (opt[0] == 0) /* end of options: the rest is padding */
            break;
        if (opt[0] == 1) {
            opt++;
            optlen--;
            continue;
        }
        if (optlen < 2 || optlen < opt[1] || opt[1] <= 2)
            return;
        optlen -= opt[1];
        opt += opt[1];
    }

    /* NextLayerType: fragments aren't reassembled. */
    if ((flagsfrags >> 13) & 0x1 || (flagsfrags & 0x1fff) != 0)
        return;
    next_proto(c, data[9], data + ihl * 4, len - ihl * 4);
}

/* decodeIPv6HeaderTLVOption + the option loop shared by the hop-by-hop
 * and destination headers. Options are read from `data` past the header's
 * own length, like gopacket. Sets *jumbo_tlv to the first jumbogram option
 * (NULL if none). Returns -1 on error. */
static int decode_tlv_options(const uint8_t *data, size_t len, size_t actual,
                              const uint8_t **jumbo_tlv)
{
    if (jumbo_tlv != NULL)
        *jumbo_tlv = NULL;
    for (size_t off = 2; off < actual;) {
        size_t rem = len - off;
        if (rem < 2)
            return -1;
        size_t opt_actual = data[off] == 0 ? 1 : (size_t)data[off + 1] + 2;
        if (rem < opt_actual)
            return -1;
        if (jumbo_tlv != NULL && *jumbo_tlv == NULL && data[off] == IPV6_HOPOPT_JUMBO)
            *jumbo_tlv = data + off;
        off += opt_actual;
    }
    return 0;
}

/* decodeIPv6ExtensionBase: the header's length, or 0 on error. */
static size_t ext_length(const uint8_t *data, size_t len)
{
    if (len < 2)
        return 0;
    size_t actual = (size_t)data[1] * 8 + 8;
    return len < actual ? 0 : actual;
}

/* decodeIPv6 / IPv6.DecodeFromBytes. */
static void decode_ipv6(struct cursor *c, struct ks_packet *out, bool outer)
{
    const uint8_t *data = c->data;
    size_t len = c->len;
    c->next = NEXT_STOP;
    if (len < 40)
        return;

    if (outer) {
        set_ip(&out->src, data + 8, 16);
        set_ip(&out->dst, data + 24, 16);
    }
    size_t length = be16(data + 4);
    uint8_t next = data[6];
    const uint8_t *payload = data + 40;
    size_t plen = len - 40;

    /* A hop-by-hop header is decoded as part of the IPv6 layer. */
    if (next == PROTO_HOPOPTS) {
        size_t actual = ext_length(payload, plen);
        const uint8_t *jumbo_tlv;
        if (actual == 0 || decode_tlv_options(payload, plen, actual, &jumbo_tlv) < 0)
            return;
        bool jumbo = false;
        uint32_t jumbo_len = 0;
        if (jumbo_tlv != NULL) { /* getIPv6HopByHopJumboLength */
            if (jumbo_tlv[1] != 4)
                return;
            jumbo_len = be32(jumbo_tlv + 2);
            if (jumbo_len <= IPV6_MAX_PAYLOAD)
                return;
            jumbo = true;
        }
        next = payload[0];
        if (jumbo && length == 0) {
            /* gopacket keeps the hop-by-hop header in the payload here, so
             * the next layer is decoded from it. */
            if (jumbo_len < plen)
                plen = jumbo_len;
            next_proto(c, next, payload, plen);
            return;
        }
        if (jumbo || length == 0)
            return;
        payload += actual;
        plen -= actual;
    }

    if (length == 0)
        return;
    if (length < plen)
        plen = length;
    next_proto(c, next, payload, plen);
}

static void decode_proto(struct cursor *c, struct ks_packet *out)
{
    const uint8_t *data = c->data;
    size_t len = c->len;
    uint8_t proto = c->proto;
    size_t actual;
    c->next = NEXT_STOP;

    switch (proto) {
    case PROTO_IPV4:
    case PROTO_IPIP:
        c->next = NEXT_IPV4;
        return;
    case PROTO_IPV6:
        c->next = NEXT_IPV6;
        return;

    case PROTO_HOPOPTS: /* decodeIPv6HopByHop */
    case PROTO_DSTOPTS: /* decodeIPv6Destination */
        actual = ext_length(data, len);
        if (actual == 0 || decode_tlv_options(data, len, actual, NULL) < 0)
            return;
        next_proto(c, data[0], data + actual, len - actual);
        return;
    case PROTO_ROUTING: /* decodeIPv6Routing: only type 0 */
        actual = ext_length(data, len);
        if (actual == 0 || data[2] != 0 || (actual - 8) % 16 != 0)
            return;
        next_proto(c, data[0], data + actual, len - actual);
        return;
    case PROTO_FRAGMENT: /* decodeIPv6Fragment: not reassembled */
        return;
    case PROTO_AH: /* decodeIPSecAH */
        if (len < 12)
            return;
        actual = ((size_t)data[1] + 2) * 4;
        if (len < actual)
            return;
        next_proto(c, data[0], data + actual, len - actual);
        return;

    case PROTO_TCP: /* decodeTCP: the layer is added even if too short */
        out->l4 = KS_L4_TCP;
        if (len >= 20) {
            out->sport = be16(data);
            out->dport = be16(data + 2);
        }
        return;
    case PROTO_UDP: /* decodeUDP: likewise */
        out->l4 = KS_L4_UDP;
        if (len >= 8) {
            out->sport = be16(data);
            out->dport = be16(data + 2);
            size_t ulen = be16(data + 4);
            if (ulen >= 8) {
                out->udp_payload = data + 8;
                out->udp_payload_len = (ulen < len ? ulen : len) - 8;
            } else if (ulen == 0) { /* jumbogram */
                out->udp_payload = data + 8;
                out->udp_payload_len = len - 8;
            }
        }
        return;
    case PROTO_UDPLITE: /* decodeUDPLite panics (no layer) if too short */
        if (len >= 8) {
            out->l4 = KS_L4_UDPLITE;
            out->sport = be16(data);
            out->dport = be16(data + 2);
        }
        return;
    case PROTO_SCTP: /* decodeSCTP: the layer is added even if too short */
        out->l4 = KS_L4_SCTP;
        if (len >= 12) {
            out->sport = be16(data);
            out->dport = be16(data + 2);
        }
        return;
    case PROTO_ICMPV4: /* decodingLayerDecoder: no layer on error */
        if (len >= 8)
            out->l4 = KS_L4_ICMPV4;
        return;
    case PROTO_ICMPV6:
        if (len >= 4)
            out->l4 = KS_L4_ICMPV6;
        return;
    default:
        /* No decoder, or one that never leads to a transport layer
         * conman reads (GRE, EtherIP, MPLS, ESP...). */
        return;
    }
}

void ks_packet_decode(const uint8_t *data, size_t len, struct ks_packet *out)
{
    memset(out, 0, sizeof(*out));
    if (len == 0)
        return;
    out->ipv4 = data[0] >> 4 == 4;

    struct cursor c = {
        .data = data,
        .len = len,
        .next = out->ipv4 ? NEXT_IPV4 : NEXT_IPV6,
    };
    /* Every layer consumes bytes, so this ends. */
    for (bool outer = true; c.next != NEXT_STOP && out->l4 == KS_L4_NONE; outer = false) {
        switch (c.next) {
        case NEXT_IPV4:
            decode_ipv4(&c, out, outer);
            break;
        case NEXT_IPV6:
            decode_ipv6(&c, out, outer);
            break;
        case NEXT_PROTO:
            decode_proto(&c, out);
            break;
        case NEXT_STOP:
            break;
        }
    }
    if (out->udp_payload != NULL)
        out->udp_payload_cap = (size_t)(data + len - out->udp_payload);
}

/* udpPortLayerType (layers/ports.go): the ports gopacket decodes UDP
 * payloads for. Only whether it is DNS matters here. */
enum udp_next { UDP_NEXT_PAYLOAD, UDP_NEXT_DNS, UDP_NEXT_OTHER };

static enum udp_next udp_port_layer_type(unsigned port)
{
    switch (port) {
    case 53:
        return UDP_NEXT_DNS;
    case 123:  /* NTP */
    case 4789: /* VXLAN */
    case 67:   /* DHCPv4 */
    case 68:
    case 546: /* DHCPv6 */
    case 547:
    case 5060: /* SIP */
    case 6343: /* SFlow */
    case 6081: /* Geneve */
    case 3784: /* BFD */
    case 2152: /* GTPv1U */
    case 623:  /* RMCP */
    case 1812: /* RADIUS */
        return UDP_NEXT_OTHER;
    default:
        return UDP_NEXT_PAYLOAD;
    }
}

bool ks_packet_udp_next_is_dns(const struct ks_packet *p)
{
    /* lazyPacket.decodeNextLayer() stops at an empty payload. */
    if (p->l4 != KS_L4_UDP || p->udp_payload == NULL || p->udp_payload_len == 0)
        return false;
    enum udp_next lt = udp_port_layer_type(p->dport);
    if (lt == UDP_NEXT_PAYLOAD)
        lt = udp_port_layer_type(p->sport);
    return lt == UDP_NEXT_DNS;
}

const char *ks_packet_protocol(const struct ks_packet *p)
{
    /* NewConnection6 passes "6" as the suffix; ICMPv4 never gets it. */
    bool v6 = !p->ipv4;
    switch (p->l4) {
    case KS_L4_TCP:
        return v6 ? "tcp6" : "tcp";
    case KS_L4_UDP:
        return v6 ? "udp6" : "udp";
    case KS_L4_UDPLITE:
        return v6 ? "udplite6" : "udplite";
    case KS_L4_SCTP:
        return v6 ? "sctp6" : "sctp";
    case KS_L4_ICMPV4:
        return "icmp";
    case KS_L4_ICMPV6:
        return v6 ? "icmp6" : "icmp";
    case KS_L4_NONE:
        break;
    }
    return NULL;
}

void ks_conn_string(const struct ks_conn *c, char *buf, size_t len)
{
    char dst[KS_IP_STRLEN];
    ks_ip_string(&c->dst_ip, dst, sizeof(dst));
    const struct ks_process *p = c->process;
    const char *path = p && p->path ? p->path : "";
    int pid = p ? p->pid : -1;
    const char *host = c->dst_host ? c->dst_host : "";
    if (host[0] != '\0')
        snprintf(buf, len, "%s (%d) -> %s (%s):%u (proto:%s uid:%lld)", path, pid, host,
                 dst, c->dst_port, c->protocol, c->uid);
    else
        snprintf(buf, len, "%s (%d) -> %s:%u (proto:%s uid:%lld)", path, pid, dst,
                 c->dst_port, c->protocol, c->uid);
}
