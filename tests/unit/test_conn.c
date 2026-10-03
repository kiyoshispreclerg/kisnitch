/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Packet decoding (daemon/conn.c): what conman.Parse() gets from gopacket,
 * including the malformed cases where gopacket still adds a layer.
 */
#include "daemon/conn.h"

#include <string.h>

#include "tests/harness.h"

/* A small packet builder. */
struct pkt {
    uint8_t b[512];
    size_t len;
};

static void put(struct pkt *p, const void *data, size_t n)
{
    memcpy(p->b + p->len, data, n);
    p->len += n;
}

static void put16(struct pkt *p, unsigned v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    put(p, b, 2);
}

/* IPv4 header without options. `total` 0 = computed later by fix_len4. */
static void ipv4(struct pkt *p, uint8_t proto, const uint8_t src[4],
                 const uint8_t dst[4], uint16_t flagsfrags)
{
    uint8_t h[20] = {0x45, 0, 0, 0, 0x12, 0x34, (uint8_t)(flagsfrags >> 8),
                     (uint8_t)flagsfrags, 64, proto, 0, 0};
    memcpy(h + 12, src, 4);
    memcpy(h + 16, dst, 4);
    put(p, h, sizeof(h));
}

static void fix_len4(struct pkt *p, size_t at)
{
    p->b[at + 2] = (uint8_t)((p->len - at) >> 8);
    p->b[at + 3] = (uint8_t)(p->len - at);
}

static const uint8_t SRC6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 1};
static const uint8_t DST6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 2};

static void ipv6(struct pkt *p, uint8_t next)
{
    uint8_t h[40] = {0x60, 0, 0, 0, 0, 0, next, 64};
    memcpy(h + 8, SRC6, 16);
    memcpy(h + 24, DST6, 16);
    put(p, h, sizeof(h));
}

static void fix_len6(struct pkt *p, size_t at)
{
    p->b[at + 4] = (uint8_t)((p->len - at - 40) >> 8);
    p->b[at + 5] = (uint8_t)(p->len - at - 40);
}

static void tcp(struct pkt *p, unsigned sport, unsigned dport)
{
    put16(p, sport);
    put16(p, dport);
    uint8_t rest[16] = {0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff};
    put(p, rest, sizeof(rest));
}

static void udp(struct pkt *p, unsigned sport, unsigned dport, const char *payload)
{
    size_t n = strlen(payload);
    put16(p, sport);
    put16(p, dport);
    put16(p, (unsigned)(8 + n));
    put16(p, 0);
    put(p, payload, n);
}

static const uint8_t A[4] = {10, 0, 0, 1}, B[4] = {93, 184, 216, 34};

static const char *ipstr(const struct ks_ip *ip)
{
    static char buf[KS_IP_STRLEN];
    ks_ip_string(ip, buf, sizeof(buf));
    return buf;
}

static void decode(const struct pkt *p, struct ks_packet *out)
{
    ks_packet_decode(p->b, p->len, out);
}

TEST(ipv4_tcp)
{
    struct pkt p = {0};
    ipv4(&p, 6, A, B, 0x4000 /* DF */);
    tcp(&p, 40000, 443);
    fix_len4(&p, 0);
    struct ks_packet k;
    decode(&p, &k);
    CHECK(k.ipv4);
    CHECK_INT_EQ(k.src.len, 4);
    CHECK_STR_EQ(ipstr(&k.src), "10.0.0.1");
    CHECK_STR_EQ(ipstr(&k.dst), "93.184.216.34");
    CHECK_INT_EQ(k.l4, KS_L4_TCP);
    CHECK_INT_EQ(k.sport, 40000);
    CHECK_INT_EQ(k.dport, 443);
    CHECK_STR_EQ(ks_packet_protocol(&k), "tcp");
}

TEST(ipv4_udp_payload)
{
    struct pkt p = {0};
    ipv4(&p, 17, B, A, 0);
    udp(&p, 53, 5353, "dns!");
    fix_len4(&p, 0);
    struct ks_packet k;
    decode(&p, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "udp");
    CHECK_INT_EQ(k.sport, 53);
    CHECK_INT_EQ(k.dport, 5353);
    CHECK_INT_EQ(k.udp_payload_len, 4);
    CHECK(memcmp(k.udp_payload, "dns!", 4) == 0);

    /* UDP length < 8: the layer is there, without payload. */
    p.b[20 + 5] = 3;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_UDP);
    CHECK(k.udp_payload == NULL);
    /* UDP length 0: jumbogram, the rest of the data. */
    p.b[20 + 5] = 0;
    decode(&p, &k);
    CHECK_INT_EQ(k.udp_payload_len, 4);
}

TEST(ipv4_length_handling)
{
    struct pkt p = {0};
    ipv4(&p, 6, A, B, 0);
    tcp(&p, 1, 2);
    struct ks_packet k;

    /* Total length 0 (TSO): the data's length. */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_TCP);
    CHECK_INT_EQ(k.dport, 2);

    /* Total length cuts the TCP header short: the layer is still added,
     * with zero ports. */
    p.b[3] = 30;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_TCP);
    CHECK_INT_EQ(k.sport, 0);
    CHECK_INT_EQ(k.dport, 0);

    /* Total length == header length: no payload, no transport. */
    p.b[3] = 20;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    CHECK(ks_packet_protocol(&k) == NULL);

    /* Longer than the data: truncated, decoded anyway. */
    p.b[2] = 0x10;
    decode(&p, &k);
    CHECK_INT_EQ(k.dport, 2);

    /* Total length < 20 is invalid; the addresses are still read. */
    p.b[2] = 0;
    p.b[3] = 19;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    CHECK_STR_EQ(ipstr(&k.src), "10.0.0.1");
}

TEST(ipv4_bad_headers)
{
    struct pkt p = {0};
    ipv4(&p, 6, A, B, 0);
    tcp(&p, 1, 2);
    fix_len4(&p, 0);
    struct ks_packet k;

    p.b[0] = 0x44; /* IHL < 5 */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[0] = 0x4f; /* IHL*4 = 60 > 40 */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);

    /* Shorter than 20 bytes: no addresses. */
    ks_packet_decode(p.b, 19, &k);
    CHECK(k.ipv4);
    CHECK_INT_EQ(k.src.len, 0);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);

    /* Empty input. */
    ks_packet_decode(p.b, 0, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
}

TEST(ipv4_options)
{
    struct pkt p = {0};
    ipv4(&p, 6, A, B, 0);
    p.b[0] = 0x47; /* 8 bytes of options */
    uint8_t opts[8] = {1, 1, 0x44, 4, 5, 0, 0, 0}; /* NOP NOP timestamp(4) EOL */
    put(&p, opts, sizeof(opts));
    tcp(&p, 7, 8);
    fix_len4(&p, 0);
    struct ks_packet k;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_TCP);
    CHECK_INT_EQ(k.dport, 8);

    p.b[23] = 2; /* option length must be > 2 */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[23] = 7; /* longer than the options left (6) */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[23] = 6; /* exactly the rest */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_TCP);
}

TEST(ipv4_fragments)
{
    struct pkt p = {0};
    ipv4(&p, 6, A, B, 0x2000); /* more fragments */
    tcp(&p, 1, 2);
    fix_len4(&p, 0);
    struct ks_packet k;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[6] = 0;
    p.b[7] = 1; /* offset 1 */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[7] = 0;
    p.b[6] = 0x80; /* the "evil" bit doesn't matter */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_TCP);
}

TEST(short_transport_headers)
{
    struct ks_packet k;
    struct pkt p = {0};
    uint8_t junk[7] = {0x12, 0x34, 0x56, 0x78, 1, 2, 3};

    ipv4(&p, 17, A, B, 0); /* UDP < 8 bytes: layer, zero ports */
    put(&p, junk, 7);
    fix_len4(&p, 0);
    decode(&p, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "udp");
    CHECK_INT_EQ(k.sport, 0);

    p.b[9] = 136; /* UDP-Lite < 8 bytes: gopacket panics, no layer */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[9] = 132; /* SCTP < 12 bytes: layer, zero ports */
    decode(&p, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "sctp");
    CHECK_INT_EQ(k.dport, 0);
    p.b[9] = 1; /* ICMPv4 < 8 bytes: no layer */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[9] = 58; /* ICMPv6 >= 4 bytes: layer */
    decode(&p, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "icmp"); /* no "6" over IPv4 */
    p.b[9] = 47; /* GRE: not followed */
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);

    struct pkt q = {0};
    ipv4(&q, 136, A, B, 0);
    put(&q, junk, 7);
    put(&q, junk, 1);
    fix_len4(&q, 0);
    decode(&q, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "udplite");
    CHECK_INT_EQ(k.sport, 0x1234);
    CHECK_INT_EQ(k.dport, 0x5678);
    q.b[9] = 1;
    decode(&q, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "icmp");
    CHECK_INT_EQ(k.sport, 0);
}

TEST(ipv6_tcp_and_extensions)
{
    struct pkt p = {0};
    ipv6(&p, 6);
    tcp(&p, 50000, 80);
    fix_len6(&p, 0);
    struct ks_packet k;
    decode(&p, &k);
    CHECK(!k.ipv4);
    CHECK_STR_EQ(ipstr(&k.src), "2001:db8::1");
    CHECK_STR_EQ(ipstr(&k.dst), "2001:db8::2");
    CHECK_STR_EQ(ks_packet_protocol(&k), "tcp6");
    CHECK_INT_EQ(k.dport, 80);

    /* hop-by-hop (PadN), destination options (Pad1 x6), routing type 0
     * without addresses, AH, then UDP. */
    struct pkt q = {0};
    ipv6(&q, 0);
    uint8_t hbh[8] = {60, 0, 1, 4, 0, 0, 0, 0};
    uint8_t dst[8] = {43, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rt[8] = {51, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ah[12] = {17, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1};
    put(&q, hbh, 8);
    put(&q, dst, 8);
    put(&q, rt, 8);
    put(&q, ah, 12);
    udp(&q, 5000, 53, "q");
    fix_len6(&q, 0);
    decode(&q, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "udp6");
    CHECK_INT_EQ(k.dport, 53);

    /* Routing types other than 0 are rejected. */
    q.b[40 + 16 + 2] = 2;
    decode(&q, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    q.b[40 + 16 + 2] = 0;
    /* A truncated TLV option in the hop-by-hop header. */
    q.b[40 + 3] = 200;
    decode(&q, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
}

TEST(ipv6_fragment_and_lengths)
{
    struct pkt p = {0};
    ipv6(&p, 44);
    uint8_t frag[8] = {6, 0, 0, 1, 0, 0, 0, 1};
    put(&p, frag, 8);
    tcp(&p, 1, 2);
    fix_len6(&p, 0);
    struct ks_packet k;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);

    struct pkt q = {0};
    ipv6(&q, 6);
    tcp(&q, 1, 2);
    decode(&q, &k); /* payload length 0 without a jumbogram: invalid */
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    CHECK_STR_EQ(ipstr(&k.src), "2001:db8::1");
    q.b[5] = 4; /* cuts TCP short */
    decode(&q, &k);
    CHECK_INT_EQ(k.l4, KS_L4_TCP);
    CHECK_INT_EQ(k.dport, 0);

    ks_packet_decode(q.b, 39, &k);
    CHECK_INT_EQ(k.src.len, 0);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
}

TEST(ipv6_jumbogram)
{
    /* A jumbo option with payload length 0: gopacket decodes the next
     * layer from the hop-by-hop header itself. Here the header's bytes
     * read as a UDP header with ports 0x1100 and 0xc204. */
    struct pkt p = {0};
    ipv6(&p, 0);
    uint8_t hbh[8] = {17, 0, 0xc2, 4, 0, 1, 0, 0};
    put(&p, hbh, 8);
    udp(&p, 1, 2, "x");
    struct ks_packet k;
    decode(&p, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "udp6");
    CHECK_INT_EQ(k.sport, 0x1100);
    CHECK_INT_EQ(k.dport, 0xc204);

    /* A jumbo option with a non-zero payload length is an error, and so is
     * a jumbo length below 65536. */
    p.b[5] = 17;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
    p.b[5] = 0;
    p.b[45] = 0;
    decode(&p, &k);
    CHECK_INT_EQ(k.l4, KS_L4_NONE);
}

TEST(tunnels_use_outer_addresses)
{
    static const uint8_t C[4] = {192, 168, 1, 1}, D[4] = {192, 168, 1, 2};
    struct pkt p = {0};
    ipv4(&p, 4, A, B, 0);
    ipv4(&p, 6, C, D, 0);
    tcp(&p, 1234, 22);
    fix_len4(&p, 20);
    fix_len4(&p, 0);
    struct ks_packet k;
    decode(&p, &k);
    CHECK_STR_EQ(ipstr(&k.src), "10.0.0.1");
    CHECK_STR_EQ(ks_packet_protocol(&k), "tcp");
    CHECK_INT_EQ(k.dport, 22);

    /* IPv6 in IPv4 keeps the IPv4 protocol names. */
    struct pkt q = {0};
    ipv4(&q, 41, A, B, 0);
    ipv6(&q, 6);
    tcp(&q, 1, 443);
    fix_len6(&q, 20);
    fix_len4(&q, 0);
    decode(&q, &k);
    CHECK(k.ipv4);
    CHECK_STR_EQ(ks_packet_protocol(&k), "tcp");
    CHECK_INT_EQ(k.dport, 443);
}

TEST(version_nibble)
{
    /* Anything but 4 is decoded as IPv6, without checking the version. */
    struct pkt p = {0};
    ipv6(&p, 58);
    uint8_t icmp[8] = {128, 0, 0, 0, 0, 1, 0, 1};
    put(&p, icmp, 8);
    fix_len6(&p, 0);
    p.b[0] = 0x00;
    struct ks_packet k;
    decode(&p, &k);
    CHECK(!k.ipv4);
    CHECK_STR_EQ(ks_packet_protocol(&k), "icmp6");
    p.b[6] = 1; /* ICMPv4 inside IPv6 is "icmp" */
    decode(&p, &k);
    CHECK_STR_EQ(ks_packet_protocol(&k), "icmp");
}

int main(void)
{
    RUN(ipv4_tcp);
    RUN(ipv4_udp_payload);
    RUN(ipv4_length_handling);
    RUN(ipv4_bad_headers);
    RUN(ipv4_options);
    RUN(ipv4_fragments);
    RUN(short_transport_headers);
    RUN(ipv6_tcp_and_extensions);
    RUN(ipv6_fragment_and_lengths);
    RUN(ipv6_jumbogram);
    RUN(tunnels_use_outer_addresses);
    RUN(version_nibble);
    return harness_report();
}
