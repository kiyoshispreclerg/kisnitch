/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The expressions of system firewall rules: port of upstream
 * daemon/firewall/nftables/{parser,rule_helpers}.go and exprs/.
 *
 * Each upstream expression (google/nftables expr.*) becomes the libnftnl
 * expression that marshals to the same netlink attributes, and anonymous
 * sets are queued in the batch as google/nftables' Conn.AddSet() does.
 * Values are parsed with Go's rules (strconv.Atoi, net.ParseIP,
 * strings.Split), quirks included, so a configuration yields the ruleset
 * upstream yields.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/fw/nft_priv.h"

#include <errno.h>
#include <libnftnl/object.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "common/netaddr.h"

/* exprs/enums.go keywords */
#define NFT_CT "ct"
#define NFT_META "meta"
#define NFT_ETHER "ether"
#define NFT_IIFNAME "iifname"
#define NFT_OIFNAME "oifname"
#define NFT_FAMILY_IP "ip"
#define NFT_FAMILY_IP6 "ip6"
#define NFT_FAMILY_INET "inet"
#define NFT_PROTO_ICMP "icmp"
#define NFT_PROTO_ICMPV6 "icmpv6"
#define NFT_PROTO_ICMPX "icmpx"
#define NFT_LOG "log"
#define NFT_LIMIT "limit"
#define NFT_QUOTA "quota"
#define NFT_NOTRACK "notrack"
#define NFT_COUNTER "counter"
#define NFT_SPORT "sport"
#define NFT_DPORT "dport"
#define NFT_SADDR "saddr"
#define NFT_DADDR "daddr"
#define NFT_PROTOCOL "protocol"

/* google/nftables set data types: magic and key length */
#define TYPE_INET_PROTO 12, 1
#define TYPE_INET_SERVICE 13, 2
#define TYPE_ICMP_TYPE 14, 1
#define TYPE_ICMP6_TYPE 29, 1

/* NFT_OBJECT_COUNTER */
#define OBJECT_COUNTER 1

/* expr.CtStateBit* */
#define CT_BIT_INVALID 1u
#define CT_BIT_ESTABLISHED 2u
#define CT_BIT_RELATED 4u
#define CT_BIT_NEW 8u

/* expr.VerdictKind */
#define VERDICT_RETURN (-5)
#define VERDICT_JUMP (-3)
#define VERDICT_DROP 0
#define VERDICT_ACCEPT 1
#define VERDICT_STOP 5

/* NAT range flags (expr.NF_NAT_RANGE_*) */
#define NAT_PROTO_RANDOM 0x4u
#define NAT_PERSISTENT 0x8u
#define NAT_PROTO_RANDOM_FULLY 0x10u

/* ---- Go helpers ------------------------------------------------------ */

/* strconv.Atoi on a 64-bit platform. */
static bool go_atoi(const char *s, long long *out)
{
    const char *p = s;
    bool neg = false;
    if (*p == '+' || *p == '-')
        neg = *p++ == '-';
    if (*p == '\0')
        return false;
    unsigned long long v = 0;
    for (; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
        unsigned d = (unsigned)(*p - '0');
        if (v > (9223372036854775808ULL - d) / 10)
            return false;
        v = v * 10 + d;
    }
    if (!neg && v > 9223372036854775807ULL)
        return false;
    *out = neg ? (long long)(0 - v) : (long long)v;
    return true;
}

/* strings.Split(s, sep) with a one-char separator: the `idx`-th piece in
 * buf (truncated to its size), false past the last one. */
static bool split_at(const char *s, char sep, size_t idx, char *buf, size_t len)
{
    const char *start = s;
    for (size_t i = 0; i < idx; i++) {
        start = strchr(start, sep);
        if (start == NULL)
            return false;
        start++;
    }
    const char *end = strchr(start, sep);
    size_t n = end != NULL ? (size_t)(end - start) : strlen(start);
    if (n >= len)
        n = len - 1;
    memcpy(buf, start, n);
    buf[n] = '\0';
    return true;
}

static size_t split_count(const char *s, char sep)
{
    size_t n = 1;
    for (; *s; s++)
        n += *s == sep;
    return n;
}

static void be16(uint8_t out[2], unsigned v)
{
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}

/* exprs.NewOperator */
static enum nft_cmp_ops new_operator(const char *op)
{
    if (strcmp(op, "!=") == 0)
        return NFT_CMP_NEQ;
    if (strcmp(op, ">") == 0)
        return NFT_CMP_GT;
    if (strcmp(op, ">=") == 0)
        return NFT_CMP_GTE;
    if (strcmp(op, "<") == 0)
        return NFT_CMP_LT;
    if (strcmp(op, "<=") == 0)
        return NFT_CMP_LTE;
    return NFT_CMP_EQ;
}

/* exprs.getProtocolCode */
static bool protocol_code(const char *v, uint8_t *out)
{
    static const struct {
        const char *name;
        uint8_t code;
    } protos[] = {
        {"tcp", IPPROTO_TCP},   {"udp", IPPROTO_UDP},       {"udplite", IPPROTO_UDPLITE},
        {"sctp", IPPROTO_SCTP}, {"dccp", IPPROTO_DCCP},     {"icmp", IPPROTO_ICMP},
        {"icmpv6", 58},         {"ah", IPPROTO_AH},         {"ethernet", 143},
        {"gre", IPPROTO_GRE},   {"ip", IPPROTO_IP},         {"ipip", IPPROTO_IPIP},
        {"l2tp", 115},          {"comp", IPPROTO_COMP},     {"igmp", IPPROTO_IGMP},
        {"esp", IPPROTO_ESP},   {"raw", IPPROTO_RAW},       {"encap", 98},
    };
    for (size_t i = 0; i < sizeof(protos) / sizeof(protos[0]); i++) {
        if (strcmp(v, protos[i].name) == 0) {
            *out = protos[i].code;
            return true;
        }
    }
    long long n;
    if (!go_atoi(v, &n))
        return false;
    *out = (uint8_t)n; /* byte(prot) */
    return true;
}

/* exprs.GetICMPType / GetICMPv6Type (gopacket's codes); 0 if unknown */
static uint8_t icmp_type(const char *t, bool v6)
{
    static const struct {
        const char *name;
        uint8_t v4, v6;
    } types[] = {
        {"echo-reply", 0, 129},
        {"echo-request", 8, 128},
        {"source-quench", 4, 0},
        {"destination-unreachable", 3, 1},
        {"router-advertisement", 9, 134},
        {"router-solicitation", 10, 133},
        {"redirect", 5, 137},
        {"time-exceeded", 11, 3},
        {"info-request", 15, 0},
        {"info-reply", 16, 0},
        {"parameter-problem", 12, 4},
        {"timestamp-request", 13, 0},
        {"timestamp-reply", 14, 0},
        {"address-mask-request", 17, 0},
        {"address-mask-reply", 18, 0},
        {"packet-too-big", 0, 2},
        {"neighbour-solicitation", 0, 135},
        {"neighbour-advertisement", 0, 136},
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        if (strcmp(t, types[i].name) == 0)
            return v6 ? types[i].v6 : types[i].v4;
    return 0;
}

/* ---- libnftnl expressions (google/nftables expr.*) ------------------- */

static struct nftnl_expr *ex(const char *name)
{
    return nftnl_expr_alloc(name);
}

#define ADD(r, e) ks_nftp_add_expr(r, e)

/* expr.Meta{Key, Register: 1, SourceRegister: sreg} */
static bool e_meta(struct nftnl_rule *r, uint32_t key, bool sreg)
{
    struct nftnl_expr *e = ex("meta");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, key);
    nftnl_expr_set_u32(e, sreg ? NFTNL_EXPR_META_SREG : NFTNL_EXPR_META_DREG, NFT_REG_1);
    return ADD(r, e);
}

/* expr.Ct{Key, Register: 1, SourceRegister: sreg} */
static bool e_ct(struct nftnl_rule *r, uint32_t key, bool sreg)
{
    struct nftnl_expr *e = ex("ct");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_CT_KEY, key);
    nftnl_expr_set_u32(e, sreg ? NFTNL_EXPR_CT_SREG : NFTNL_EXPR_CT_DREG, NFT_REG_1);
    return ADD(r, e);
}

/* expr.Payload{DestRegister: 1, Base, Offset, Len} */
static bool e_payload(struct nftnl_rule *r, uint32_t base, uint32_t offset, uint32_t len)
{
    struct nftnl_expr *e = ex("payload");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);
    return ADD(r, e);
}

/* expr.Immediate{Register, Data} */
static bool e_immediate(struct nftnl_rule *r, uint32_t reg, const void *data, uint32_t len)
{
    struct nftnl_expr *e = ex("immediate");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, reg);
    nftnl_expr_set(e, NFTNL_EXPR_IMM_DATA, data, len);
    return ADD(r, e);
}

/* expr.Verdict{Kind, Chain} */
static bool e_verdict(struct nftnl_rule *r, int kind, const char *chain)
{
    struct nftnl_expr *e = ex("immediate");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, (uint32_t)kind);
    if (chain != NULL && chain[0] != '\0')
        nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, chain);
    return ADD(r, e);
}

/* expr.Range{Op, Register: 1, FromData, ToData}; empty data is omitted */
static bool e_range(struct nftnl_rule *r, uint32_t op, const void *from, uint32_t flen,
                    const void *to, uint32_t tlen)
{
    struct nftnl_expr *e = ex("range");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_RANGE_SREG, NFT_REG_1);
    nftnl_expr_set_u32(e, NFTNL_EXPR_RANGE_OP, op);
    if (flen > 0)
        nftnl_expr_set(e, NFTNL_EXPR_RANGE_FROM_DATA, from, flen);
    if (tlen > 0)
        nftnl_expr_set(e, NFTNL_EXPR_RANGE_TO_DATA, to, tlen);
    return ADD(r, e);
}

/* expr.Lookup{SourceRegister: 1, SetName, SetID} */
static bool e_lookup(struct nftnl_rule *r, const char *set, uint32_t id)
{
    struct nftnl_expr *e = ex("lookup");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SREG, NFT_REG_1);
    nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set);
    nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, id);
    return ADD(r, e);
}

/* ---- sets (Conn.AddSet) --------------------------------------------- */

#define ANON_SET_NAME "__set%d"

struct elems {
    uint8_t (*v)[2];
    size_t n, cap;
    uint32_t len; /* key length: 1 or 2 */
};

static bool elems_add(struct elems *e, const uint8_t *key)
{
    if (e->n == e->cap) {
        size_t cap = e->cap ? e->cap * 2 : 8;
        uint8_t (*v)[2] = realloc(e->v, cap * sizeof(*v));
        if (v == NULL)
            return false;
        e->v = v;
        e->cap = cap;
    }
    memcpy(e->v[e->n++], key, e->len);
    return true;
}

/* An anonymous constant set (NEWSET, then NEWSETELEM if it has elements).
 * Returns its id, or 0 if it couldn't be queued. */
static uint32_t queue_anon_set(struct ks_nft *n, const struct table_entry *t, uint32_t magic,
                               uint32_t keylen, const struct elems *el)
{
    uint32_t id = ++n->set_id;
    struct nftnl_set *s = nftnl_set_alloc();
    if (s == NULL)
        return 0;
    nftnl_set_set_str(s, NFTNL_SET_TABLE, t->name);
    nftnl_set_set_str(s, NFTNL_SET_NAME, ANON_SET_NAME);
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, t->fam);
    nftnl_set_set_u32(s, NFTNL_SET_FLAGS, NFT_SET_ANONYMOUS | NFT_SET_CONSTANT);
    nftnl_set_set_u32(s, NFTNL_SET_KEY_TYPE, magic);
    nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, keylen);
    nftnl_set_set_u32(s, NFTNL_SET_ID, id);
    nftnl_set_set_u32(s, NFTNL_SET_DESC_SIZE, (uint32_t)el->n);
    /* "semantically useless, kept for binary compatibility with nft" */
    static const char udata[] = "\x00\x04\x02\x00\x00\x00";
    nftnl_set_set_data(s, NFTNL_SET_USERDATA, udata, 6);

    char *room = ks_nftp_batch_room(n);
    if (room == NULL) {
        nftnl_set_free(s);
        return 0;
    }
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_NEWSET, t->fam,
                                                 NLM_F_CREATE | NLM_F_ACK, n->seq++);
    nftnl_set_nlmsg_build_payload(nlh, s);
    ks_nftp_batch_added(n);

    if (el->n > 0) {
        for (size_t i = 0; i < el->n; i++) {
            struct nftnl_set_elem *e = nftnl_set_elem_alloc();
            if (e == NULL) {
                nftnl_set_free(s);
                n->batch_full = true;
                return 0;
            }
            nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, el->v[i], keylen);
            nftnl_set_elem_add(s, e);
        }
        room = ks_nftp_batch_room(n);
        if (room == NULL) {
            nftnl_set_free(s);
            return 0;
        }
        nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_NEWSETELEM, t->fam,
                                    NLM_F_CREATE | NLM_F_ACK, n->seq++);
        nftnl_set_elems_nlmsg_build_payload(nlh, s);
        ks_nftp_batch_added(n);
    }
    nftnl_set_free(s);
    return id;
}

/* ---- rule_helpers.go ------------------------------------------------- */

/* NewExprPort */
static bool new_port(struct nftnl_rule *r, const char *port, enum nft_cmp_ops op)
{
    long long p;
    if (!go_atoi(port, &p))
        return false;
    uint8_t d[2];
    be16(d, (unsigned)(uint16_t)p);
    return ks_nftp_e_cmp(r, op, d, 2);
}

/* buildPortsRule */
static bool build_ports_rule(struct ks_nft *n, struct nftnl_rule *r, const char *table,
                             const char *family, const char *ports, enum nft_cmp_ops op)
{
    struct table_entry *t = ks_nftp_get_table(n, table, family);
    if (t == NULL) {
        ks_warning("%s proto.ports statement error: Invalid table (%s, %s)", LOG_TAG, table,
                   family);
        return false;
    }
    if (strchr(ports, ',') != NULL) {
        struct elems el = {.len = 2};
        char piece[64];
        for (size_t i = 0; split_at(ports, ',', i, piece, sizeof(piece)); i++) {
            long long p;
            if (!go_atoi(piece, &p))
                continue;
            uint8_t d[2];
            be16(d, (unsigned)(uint16_t)p);
            if (!elems_add(&el, d)) {
                free(el.v);
                return false;
            }
        }
        uint32_t id = queue_anon_set(n, t, TYPE_INET_SERVICE, &el);
        free(el.v);
        return id != 0 && e_lookup(r, ANON_SET_NAME, id);
    }
    if (strchr(ports, '-') != NULL) {
        /* NewExprPortRange */
        char a[64], b[64];
        long long from, to;
        split_at(ports, '-', 0, a, sizeof(a));
        split_at(ports, '-', 1, b, sizeof(b));
        if (!go_atoi(a, &from) || !go_atoi(b, &to)) {
            ks_warning("%s invalid portRange: %s", LOG_TAG, ports);
            return false;
        }
        uint8_t f[2], tt[2];
        be16(f, (unsigned)(uint16_t)from);
        be16(tt, (unsigned)(uint16_t)to);
        return e_range(r, op, f, 2, tt, 2);
    }
    if (!new_port(r, ports, op)) {
        ks_warning("%s proto.ports statement error: invalid port %s", LOG_TAG, ports);
        return false;
    }
    return true;
}

/* NewExprPortDirection */
static bool port_direction(struct nftnl_rule *r, const char *key)
{
    if (strcmp(key, NFT_DPORT) == 0)
        return e_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2);
    if (strcmp(key, NFT_SPORT) == 0)
        return e_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2);
    return false;
}

/* NewExprProtocol: meta l4proto, plus `== proto` for the known ones. */
static bool new_protocol(struct nftnl_rule *r, const char *proto)
{
    static const struct {
        const char *name;
        uint8_t code;
    } p[] = {
        {"udp", IPPROTO_UDP},   {"tcp", IPPROTO_TCP},   {"udplite", IPPROTO_UDPLITE},
        {"sctp", IPPROTO_SCTP}, {"dccp", IPPROTO_DCCP}, {"icmp", IPPROTO_ICMP},
        {"icmpv6", 58},
    };
    if (strcmp(proto, "l4proto") == 0)
        return e_meta(r, NFT_META_L4PROTO, false);
    for (size_t i = 0; i < sizeof(p) / sizeof(p[0]); i++)
        if (strcmp(proto, p[i].name) == 0)
            return e_meta(r, NFT_META_L4PROTO, false) &&
                   ks_nftp_e_cmp(r, NFT_CMP_EQ, &p[i].code, 1);
    return false;
}

/* buildL4ProtoRule */
static bool build_l4proto_rule(struct ks_nft *n, struct nftnl_rule *r, const char *table,
                               const char *family, const char *prots, enum nft_cmp_ops op)
{
    struct table_entry *t = ks_nftp_get_table(n, table, family);
    if (t == NULL) {
        ks_warning("%s meta.l4proto statement error: Invalid table (%s, %s)", LOG_TAG, table,
                   family);
        return false;
    }
    if (strchr(prots, ',') != NULL) {
        struct elems el = {.len = 1};
        char piece[64];
        for (size_t i = 0; split_at(prots, ',', i, piece, sizeof(piece)); i++) {
            uint8_t code;
            if (protocol_code(piece, &code) && !elems_add(&el, &code)) {
                free(el.v);
                return false;
            }
        }
        uint32_t id = queue_anon_set(n, t, TYPE_INET_PROTO, &el);
        free(el.v);
        return id != 0 && e_lookup(r, ANON_SET_NAME, id);
    }
    /* NewExprL4Proto: an unknown protocol is 0 */
    uint8_t code = 0;
    protocol_code(prots, &code);
    return ks_nftp_e_cmp(r, op, &code, 1);
}

/* buildICMPRule */
static bool build_icmp_rule(struct ks_nft *n, struct nftnl_rule *r, const char *table,
                            const char *family, const char *version,
                            const struct ks_fw_statement *st)
{
    struct table_entry *t = ks_nftp_get_table(n, table, family);
    if (t == NULL)
        return false;
    bool v6 = strcmp(version, NFT_PROTO_ICMPV6) == 0;
    uint32_t offset = 0;
    struct elems el = {.len = 1};
    if (!new_protocol(r, version))
        return false;
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        if (strcmp(v->key, "type") == 0) {
            char piece[64];
            for (size_t j = 0; split_at(v->value, ',', j, piece, sizeof(piece)); j++) {
                uint8_t code = icmp_type(piece, v6);
                if (!elems_add(&el, &code)) {
                    free(el.v);
                    return false;
                }
            }
        } else if (strcmp(v->key, "code") == 0) {
            offset = 1; /* TODO upstream */
        }
    }
    bool ok = e_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, offset, 1);
    if (ok && el.n == 1) {
        ok = ks_nftp_e_cmp(r, NFT_CMP_EQ, el.v[0], 1);
    } else if (ok) {
        uint32_t id = v6 ? queue_anon_set(n, t, TYPE_ICMP6_TYPE, &el)
                         : queue_anon_set(n, t, TYPE_ICMP_TYPE, &el);
        ok = id != 0 && e_lookup(r, ANON_SET_NAME, id);
    }
    free(el.v);
    return ok;
}

/* NewExprCtState: every value is a comma-separated list of states. */
static bool ct_state_mask(const struct ks_fw_statement *st, uint32_t *mask)
{
    *mask = 0;
    for (size_t i = 0; i < st->values.len; i++) {
        const char *flags = KS_SYSFW_VALUE(st, i)->value;
        char piece[64];
        for (size_t j = 0; split_at(flags, ',', j, piece, sizeof(piece)); j++) {
            for (char *c = piece; *c; c++)
                if (*c >= 'A' && *c <= 'Z')
                    *c = (char)(*c - 'A' + 'a');
            if (strcmp(piece, "new") == 0)
                *mask |= CT_BIT_NEW;
            else if (strcmp(piece, "established") == 0)
                *mask |= CT_BIT_ESTABLISHED;
            else if (strcmp(piece, "related") == 0)
                *mask |= CT_BIT_RELATED;
            else if (strcmp(piece, "invalid") == 0)
                *mask |= CT_BIT_INVALID;
            else {
                ks_warning("%s ct set state error: Invalid conntrack flag: %s", LOG_TAG, piece);
                return false;
            }
        }
    }
    return true;
}

/* NewExprCtMark */
static bool ct_mark(struct nftnl_rule *r, bool set, const char *value, enum nft_cmp_ops op)
{
    long long mark;
    if (!go_atoi(value, &mark)) {
        ks_warning("%s ct mark error: Invalid conntrack mark: %s", LOG_TAG, value);
        return false;
    }
    uint32_t m = (uint32_t)mark; /* NativeEndian */
    if (!e_immediate(r, NFT_REG_1, &m, 4) || !e_ct(r, NFT_CT_MARK, set))
        return false;
    return set || ks_nftp_e_cmp(r, op, &m, 4);
}

/* buildConntrackRule */
static bool build_conntrack_rule(struct nftnl_rule *r, const struct ks_fw_statement *st,
                                 enum nft_cmp_ops op)
{
    bool set_mark = false;
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        if (strcmp(v->key, "state") == 0) {
            uint32_t mask, zero = 0;
            static const uint8_t zero4[4] = {0, 0, 0, 0};
            return ct_state_mask(st, &mask) && e_ct(r, NFT_CT_STATE, false) &&
                   ks_nftp_e_bitwise(r, &mask, &zero, 4) &&
                   ks_nftp_e_cmp(r, NFT_CMP_NEQ, zero4, 4);
        }
        if (strcmp(v->key, "set") == 0) {
            set_mark = true;
        } else if (strcmp(v->key, "mark") == 0) {
            return ct_mark(r, set_mark, v->value, op);
        } else {
            ks_warning("%s invalid conntrack option: &{%s %s}", LOG_TAG, v->key, v->value);
            return false;
        }
    }
    return true;
}

/* ---- exprs/ ------------------------------------------------------ */

/* NewExprMeta: the first known key decides. */
static bool new_meta(struct nftnl_rule *r, const struct ks_fw_statement *st,
                     enum nft_cmp_ops op)
{
    bool set_mark = false;
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        long long val;
        if (strcmp(v->key, "set") == 0) {
            set_mark = true;
            continue;
        }
        if (strcmp(v->key, "mark") == 0) {
            if (!go_atoi(v->value, &val))
                goto bad_value;
            uint32_t m = (uint32_t)val;
            if (set_mark)
                return e_immediate(r, NFT_REG_1, &m, 4) && e_meta(r, NFT_META_MARK, true);
            return e_meta(r, NFT_META_MARK, false) && ks_nftp_e_cmp(r, op, &m, 4);
        }
        if (strcmp(v->key, "l4proto") == 0)
            return e_meta(r, NFT_META_L4PROTO, false);
        uint32_t key = 0;
        if (strcmp(v->key, "priority") == 0)
            key = NFT_META_PRIORITY;
        else if (strcmp(v->key, "skuid") == 0)
            key = NFT_META_SKUID;
        else if (strcmp(v->key, "skgid") == 0)
            key = NFT_META_SKGID;
        else if (strcmp(v->key, "protocol") == 0)
            key = NFT_META_PROTOCOL;
        if (key != 0) {
            uint8_t code; /* getProtocolCode: numbers become a byte */
            if (!protocol_code(v->value, &code))
                goto bad_value;
            uint32_t d = code;
            return e_meta(r, key, set_mark) && ks_nftp_e_cmp(r, op, &d, 4);
        }
        if (strcmp(v->key, "nftrace") == 0) {
            if (!go_atoi(v->value, &val))
                goto bad_value;
            if (val != 0 && val != 1) {
                ks_warning("%s meta statement error: nftables Invalid nftrace value: %lld. Only "
                           "1 or 0 allowed", LOG_TAG, val);
                return false;
            }
            uint32_t d = (uint32_t)val;
            return e_meta(r, NFT_META_NFTRACE, false) && ks_nftp_e_cmp(r, op, &d, 4);
        }
        continue;
    bad_value:
        ks_warning("%s meta statement error: invalid value %s", LOG_TAG, v->value);
        return false;
    }
    ks_warning("%s meta statement error: nftables meta keyword not supported yet, open a new "
               "issue on github", LOG_TAG);
    return false;
}

/* parseMACAddr: six colon-separated hex bytes (hex.DecodeString of each,
 * its first byte used). */
static bool parse_mac(const char *s, uint8_t mac[6])
{
    if (split_count(s, ':') != 6)
        return false;
    char piece[64];
    for (size_t i = 0; i < 6; i++) {
        split_at(s, ':', i, piece, sizeof(piece));
        size_t len = strlen(piece);
        if (len == 0 || len % 2 != 0)
            return false;
        for (size_t j = 0; j < len; j++) {
            char c = piece[j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        unsigned b;
        if (sscanf(piece, "%2x", &b) != 1)
            return false;
        mac[i] = (uint8_t)b;
    }
    return true;
}

/* NewExprEther */
static bool new_ether(struct nftnl_rule *r, const struct ks_fw_statement *st)
{
    static const uint8_t ether[2] = {0x01, 0x00};
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        uint32_t dir = strcmp(v->key, NFT_DADDR) == 0 ? 0 : 6;
        uint8_t mac[6];
        if (!parse_mac(v->value, mac)) {
            ks_warning("%s ether statement error: Invalid MAC address: %s", LOG_TAG, v->value);
            return false;
        }
        if (!e_meta(r, NFT_META_IIFTYPE, false) || !ks_nftp_e_cmp(r, NFT_CMP_EQ, ether, 2) ||
            !e_payload(r, NFT_PAYLOAD_LL_HEADER, dir, 6) ||
            !ks_nftp_e_cmp(r, NFT_CMP_EQ, mac, 6))
            return false;
    }
    return true;
}

/* NewExprIface */
static bool new_iface(struct nftnl_rule *r, const char *iface, bool out, enum nft_cmp_ops op)
{
    uint8_t buf[16] = {0};
    size_t len = strlen(iface);
    if (!e_meta(r, out ? NFT_META_OIFNAME : NFT_META_IIFNAME, false))
        return false;
    /* ifname(): a trailing "*" matches the prefix */
    if (iface[len - 1] == '*')
        return ks_nftp_e_cmp(r, op, iface, (uint32_t)(len - 1));
    memcpy(buf, iface, len < sizeof(buf) ? len : sizeof(buf));
    return ks_nftp_e_cmp(r, op, buf, sizeof(buf));
}

/* net.ParseIP(s).To4(): 4 bytes, 0 for IPv6, -1 if invalid */
static int parse_ip4(const char *s, uint8_t out[4])
{
    struct ks_ip ip;
    if (ks_ip_parse(s, &ip) < 0)
        return -1;
    return ks_ip_to4(&ip, out) ? 4 : 0;
}

/* NewExprIP */
static bool new_ip(struct nftnl_rule *r, const char *family, const struct ks_fw_statement *st,
                   enum nft_cmp_ops op)
{
    if (strcmp(family, NFT_FAMILY_INET) == 0) {
        uint8_t ipv4 = NFPROTO_IPV4;
        if (!e_meta(r, NFT_META_NFPROTO, false) || !ks_nftp_e_cmp(r, NFT_CMP_EQ, &ipv4, 1))
            return false;
    }
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        if (strcmp(v->key, NFT_SADDR) == 0 || strcmp(v->key, NFT_DADDR) == 0) {
            if (!e_payload(r, NFT_PAYLOAD_NETWORK_HEADER,
                           strcmp(v->key, NFT_DADDR) == 0 ? 16 : 12, 4))
                return false;
            uint8_t a[4], b[4];
            if (strchr(v->value, '-') == NULL) {
                int la = parse_ip4(v->value, a);
                if (la < 0) {
                    ks_warning("%s addr statement error: Invalid IP: %s", LOG_TAG, v->value);
                    return false;
                }
                if (!ks_nftp_e_cmp(r, op, a, (uint32_t)la))
                    return false;
            } else {
                char x[64], y[64];
                split_at(v->value, '-', 0, x, sizeof(x));
                split_at(v->value, '-', 1, y, sizeof(y));
                int la = parse_ip4(x, a), lb = parse_ip4(y, b);
                if (la < 0 || lb < 0) {
                    ks_warning("%s addr statement error: Invalid IPs range: [%s %s]", LOG_TAG,
                               x, y);
                    return false;
                }
                if (!e_range(r, op, a, (uint32_t)la, b, (uint32_t)lb))
                    return false;
            }
        } else if (strcmp(v->key, NFT_PROTOCOL) == 0) {
            uint8_t code;
            if (!e_payload(r, NFT_PAYLOAD_NETWORK_HEADER, 9, 1))
                return false;
            if (!protocol_code(v->value, &code)) {
                ks_warning("%s addr statement error: invalid protocol %s", LOG_TAG, v->value);
                return false;
            }
            if (!ks_nftp_e_cmp(r, op, &code, 1))
                return false;
        }
    }
    return true;
}

/* NewExprLog */
static bool new_log(struct nftnl_rule *r, const struct ks_fw_statement *st)
{
    static const char *const levels[] = {"emerg", "alert", "crit",  "err",  "warn",
                                         "notice", "info", "debug", "audit"};
    const char *prefix = "opensnitch";
    bool has_level = false;
    uint32_t level = 0;
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        if (strcmp(v->key, "prefix") == 0) {
            if (v->value[0] == '\0') {
                ks_warning("%s log statement error", LOG_TAG);
                return false;
            }
            prefix = v->value;
        } else if (strcmp(v->key, "level") == 0) {
            size_t l;
            for (l = 0; l < sizeof(levels) / sizeof(levels[0]); l++)
                if (strcmp(v->value, levels[l]) == 0)
                    break;
            if (l == sizeof(levels) / sizeof(levels[0])) {
                ks_warning("Invalid log level: %s", v->value);
                ks_warning("%s log statement error", LOG_TAG);
                return false;
            }
            has_level = true;
            level = (uint32_t)l;
        }
    }
    struct nftnl_expr *e = ex("log");
    if (e == NULL)
        return false;
    nftnl_expr_set_str(e, NFTNL_EXPR_LOG_PREFIX, prefix);
    if (has_level)
        nftnl_expr_set_u32(e, NFTNL_EXPR_LOG_LEVEL, level);
    return ADD(r, e);
}

/* NewExprLimit */
static bool new_limit(struct nftnl_rule *r, const struct ks_fw_statement *st)
{
    uint32_t type = NFT_LIMIT_PKTS, burst = 0, flags = 0;
    uint64_t rate = 0, unit = 1;
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        if (strcmp(v->key, "over") == 0) {
            flags = NFT_LIMIT_F_INV;
        } else if (strcmp(v->key, "units") == 0) {
            char *end;
            errno = 0;
            unsigned long long x = strtoull(v->value, &end, 10);
            if (v->value[0] < '0' || v->value[0] > '9' || *end != '\0' || errno != 0) {
                ks_warning("%s Invalid limit rate: %s", LOG_TAG, v->value);
                return false;
            }
            rate = x;
        } else if (strcmp(v->key, "burst") == 0) {
            long long b;
            if (!go_atoi(v->value, &b) || b == 0) {
                ks_warning("%s Invalid burst limit: %s", LOG_TAG, v->value);
                return false;
            }
            burst = (uint32_t)b;
        } else if (strcmp(v->key, "rate-units") == 0) {
            /* getLimitRate: must come after the rate */
            if (strcmp(v->value, "kbytes") == 0) {
                rate *= 1024;
                type = NFT_LIMIT_PKT_BYTES;
            } else if (strcmp(v->value, "mbytes") == 0) {
                rate = rate * 1024 * 1024;
                type = NFT_LIMIT_PKT_BYTES;
            } else {
                type = NFT_LIMIT_PKTS;
                char *end;
                unsigned long long x = strtoull(v->value, &end, 10);
                rate = (v->value[0] >= '0' && v->value[0] <= '9' && *end == '\0') ? x : 0;
            }
        } else if (strcmp(v->key, "time-units") == 0) {
            if (strcmp(v->value, "minute") == 0)
                unit = 60;
            else if (strcmp(v->value, "hour") == 0)
                unit = 3600;
            else if (strcmp(v->value, "day") == 0)
                unit = 86400;
            else
                unit = 1;
        }
    }
    struct nftnl_expr *e = ex("limit");
    if (e == NULL)
        return false;
    nftnl_expr_set_u64(e, NFTNL_EXPR_LIMIT_RATE, rate);
    nftnl_expr_set_u64(e, NFTNL_EXPR_LIMIT_UNIT, unit);
    nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_BURST, burst);
    nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_TYPE, type);
    nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_FLAGS, flags);
    return ADD(r, e);
}

/* strconv.ParseInt(s, 10, 64) */
static bool parse_int64(const char *s, long long *out)
{
    return go_atoi(s, out);
}

/* NewQuota */
static bool new_quota(struct nftnl_rule *r, const struct ks_fw_statement *st)
{
    bool over = false;
    long long bytes = 0, used = 0;
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        long long b;
        if (strcmp(v->key, "over") == 0) {
            over = true;
            continue;
        }
        long long mult;
        if (strcmp(v->key, "bytes") == 0 || strcmp(v->key, "used") == 0)
            mult = 1;
        else if (strcmp(v->key, "kbytes") == 0)
            mult = 1024;
        else if (strcmp(v->key, "mbytes") == 0)
            mult = 1024 * 1024;
        else if (strcmp(v->key, "gbytes") == 0)
            mult = 1024LL * 1024 * 1024;
        else {
            ks_warning("%s quota statement error: invalid quota key: %s", LOG_TAG, v->key);
            return false;
        }
        if (!parse_int64(v->value, &b)) {
            ks_warning("%s quota statement error: invalid quota bytes: %s", LOG_TAG, v->value);
            return false;
        }
        if (strcmp(v->key, "used") == 0)
            used = b;
        else
            bytes = (long long)((unsigned long long)b * (unsigned long long)mult);
    }
    if (bytes == 0) {
        ks_warning("%s quota statement error: quota bytes cannot be 0", LOG_TAG);
        return false;
    }
    struct nftnl_expr *e = ex("quota");
    if (e == NULL)
        return false;
    nftnl_expr_set_u64(e, NFTNL_EXPR_QUOTA_BYTES, (uint64_t)bytes);
    nftnl_expr_set_u64(e, NFTNL_EXPR_QUOTA_CONSUMED, (uint64_t)used);
    nftnl_expr_set_u32(e, NFTNL_EXPR_QUOTA_FLAGS, over ? NFT_QUOTA_F_INV : 0);
    return ADD(r, e);
}

/* The "counter" statement: a named counter object, committed right away,
 * and a reference to it. */
static bool new_counter(struct ks_nft *n, struct nftnl_rule *r, const char *table,
                        const char *chain, const char *family,
                        const struct ks_fw_statement *st)
{
    struct table_entry *t = ks_nftp_get_table(n, table, family);
    if (t == NULL) {
        ks_warning("%s Error getting table counter: %s, %s, %s", LOG_TAG, table, chain, family);
        return false;
    }
    const char *name = "opensnitch";
    uint64_t bytes = 0, packets = 0;
    for (size_t i = 0; i < st->values.len; i++) {
        const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
        if (strcmp(v->key, "name") == 0)
            name = v->value;
        else if (strcmp(v->key, "bytes") == 0)
            bytes = 1;
        else if (strcmp(v->key, "packets") == 0)
            packets = 1;
    }
    struct nftnl_obj *o = nftnl_obj_alloc();
    char *room = ks_nftp_batch_room(n);
    if (o == NULL || room == NULL) {
        nftnl_obj_free(o);
        ks_warning("Error adding counter %s", name);
        return false;
    }
    nftnl_obj_set_str(o, NFTNL_OBJ_TABLE, t->name);
    nftnl_obj_set_str(o, NFTNL_OBJ_NAME, name);
    nftnl_obj_set_u32(o, NFTNL_OBJ_TYPE, OBJECT_COUNTER);
    nftnl_obj_set_u32(o, NFTNL_OBJ_FAMILY, t->fam);
    nftnl_obj_set_u64(o, NFTNL_OBJ_CTR_BYTES, bytes);
    nftnl_obj_set_u64(o, NFTNL_OBJ_CTR_PKTS, packets);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_NEWOBJ, t->fam,
                                                 NLM_F_CREATE | NLM_F_ACK, n->seq++);
    nftnl_obj_nlmsg_build_payload(nlh, o);
    nftnl_obj_free(o);
    ks_nftp_batch_added(n);
    if (!ks_nftp_commit(n)) {
        ks_warning("Error creating counter %s", name);
        return false;
    }
    ks_debug("%s counter %s created (%s, %s, %s)", LOG_TAG, name, table, chain, family);
    struct nftnl_expr *e = ex("objref");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_OBJREF_IMM_TYPE, OBJECT_COUNTER);
    nftnl_expr_set_str(e, NFTNL_EXPR_OBJREF_IMM_NAME, name);
    return ADD(r, e);
}

/* parseExpression */
bool ks_nftp_parse_expression(struct ks_nft *n, struct nftnl_rule *r, const char *table,
                              const char *chain, const char *family,
                              const struct ks_fw_expression *expr)
{
    const struct ks_fw_statement *st = expr->statement;
    if (st == NULL) /* a nil Statement makes upstream panic */
        return false;
    enum nft_cmp_ops op = new_operator(st->op);
    const char *name = st->name;

    if (strcmp(name, NFT_CT) == 0) {
        if (!build_conntrack_rule(r, st, op)) {
            ks_warning("%s Ct statement error", LOG_TAG);
            return false;
        }
        return true;
    }
    if (strcmp(name, NFT_META) == 0) {
        if (!new_meta(r, st, op))
            return false;
        for (size_t i = 0; i < st->values.len; i++) {
            const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
            if (strcmp(v->key, "l4proto") == 0) {
                if (!build_l4proto_rule(n, r, table, family, v->value, op))
                    return false;
            } else if (strcmp(v->key, NFT_DPORT) == 0 || strcmp(v->key, NFT_SPORT) == 0) {
                if (!port_direction(r, v->key) ||
                    !build_ports_rule(n, r, table, family, v->value, op))
                    return false;
            }
        }
        return true;
    }
    if (strcmp(name, NFT_ETHER) == 0)
        return new_ether(r, st);
    if (strcmp(name, NFT_IIFNAME) == 0 || strcmp(name, NFT_OIFNAME) == 0) {
        /* the interface name is the Key of the first value */
        const char *iface = st->values.len > 0 ? KS_SYSFW_VALUE(st, 0)->key : "";
        if (iface[0] == '\0') {
            ks_warning("%s network interface statement error: %s", LOG_TAG, name);
            return false;
        }
        return new_iface(r, iface, strcmp(name, NFT_OIFNAME) == 0, op);
    }
    if (strcmp(name, NFT_FAMILY_IP) == 0 || strcmp(name, NFT_FAMILY_IP6) == 0)
        return new_ip(r, family, st, op);
    if (strcmp(name, NFT_PROTO_ICMP) == 0 || strcmp(name, NFT_PROTO_ICMPV6) == 0) {
        if (!build_icmp_rule(n, r, table, family, name, st)) {
            ks_warning("%s icmp statement error", LOG_TAG);
            return false;
        }
        return true;
    }
    if (strcmp(name, NFT_LOG) == 0)
        return new_log(r, st);
    if (strcmp(name, NFT_LIMIT) == 0)
        return new_limit(r, st);
    if (strcmp(name, "udp") == 0 || strcmp(name, "tcp") == 0 || strcmp(name, "udplite") == 0 ||
        strcmp(name, "sctp") == 0 || strcmp(name, "dccp") == 0) {
        if (!new_protocol(r, name))
            return false;
        for (size_t i = 0; i < st->values.len; i++) {
            const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, i);
            if (strcmp(v->key, NFT_DPORT) != 0 && strcmp(v->key, NFT_SPORT) != 0)
                continue;
            if (!port_direction(r, v->key) ||
                !build_ports_rule(n, r, table, family, v->value, op))
                return false;
        }
        return true;
    }
    if (strcmp(name, NFT_QUOTA) == 0)
        return new_quota(r, st);
    if (strcmp(name, NFT_NOTRACK) == 0) {
        struct nftnl_expr *e = ex("notrack");
        return e != NULL && ADD(r, e);
    }
    if (strcmp(name, NFT_COUNTER) == 0)
        return new_counter(n, r, table, chain, family, st);
    /* unknown statements add nothing */
    return true;
}

/* ---- verdict.go, nat.go --------------------------------------------- */

/* NewExprNATFlags: the whole parameter string, comma separated. */
static uint32_t nat_flags(const char *parms)
{
    uint32_t f = 0;
    char piece[128];
    for (size_t i = 0; split_at(parms, ',', i, piece, sizeof(piece)); i++) {
        if (strcmp(piece, "random") == 0)
            f |= NAT_PROTO_RANDOM;
        else if (strcmp(piece, "fully-random") == 0)
            f |= NAT_PROTO_RANDOM_FULLY;
        else if (strcmp(piece, "persistent") == 0)
            f |= NAT_PERSISTENT;
    }
    return f;
}

/* NewExprNAT: queues the immediates loading the address and port of
 * "[to] [ip][:port]". Returns false on a parse error (what was added
 * before the error stays, as upstream's partial list does). */
static bool new_nat(struct nftnl_rule *r, const char *parms, const char *verdict,
                    bool *reg_addr, bool *reg_proto)
{
    *reg_addr = *reg_proto = false;
    char first[256], target[256];
    size_t idx = 0;
    split_at(parms, ' ', 0, first, sizeof(first));
    if (strcmp(first, "to") == 0)
        idx++;
    if (!split_at(parms, ' ', idx, target, sizeof(target))) {
        ks_warning("error adding %s verdict: Invalid parms: %s", verdict, parms);
        return false;
    }
    char ip[256], port[256];
    split_at(target, ':', 0, ip, sizeof(ip));
    bool masq = strcmp(verdict, "masquerade") == 0;
    if (ip[0] != '\0' && !masq) {
        uint8_t a[4];
        int la = parse_ip4(ip, a);
        if (la < 0) {
            ks_warning("error adding %s verdict: Invalid IP: %s", verdict, ip);
            return false;
        }
        if (!e_immediate(r, NFT_REG_1, a, (uint32_t)la))
            return false;
        *reg_addr = true;
    }
    if (split_count(target, ':') == 2) {
        split_at(target, ':', 1, port, sizeof(port));
        long long p;
        if (!go_atoi(port, &p)) {
            ks_warning("error adding %s verdict: Invalid Port: %s", verdict, port);
            return false;
        }
        uint32_t reg = 2;
        if (strcmp(verdict, "tproxy") == 0 || masq || strcmp(verdict, "redirect") == 0)
            reg = 1;
        uint8_t d[2];
        be16(d, (unsigned)(uint16_t)p);
        if (!e_immediate(r, reg, d, 2))
            return false;
        *reg_proto = true;
    }
    return true;
}

/* expr.NAT: snat (0) or dnat (1), IPv4 */
static bool e_nat(struct nftnl_rule *r, uint32_t type, bool reg_addr, bool reg_proto,
                  uint32_t flags)
{
    struct nftnl_expr *e = ex("nat");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_TYPE, type);
    nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_FAMILY, NFPROTO_IPV4);
    if (reg_addr)
        nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
    if (reg_proto)
        nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MIN, NFT_REG_2);
    if (flags != 0)
        nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_FLAGS, flags);
    return ADD(r, e);
}

/* NewExprReject: "with <what> <how>" */
static bool e_reject(struct nftnl_rule *r, const char *parms)
{
    /* gopacket's ICMPv4 and ICMPv6 codes, and nft's ICMPX codes */
    uint32_t type = NFT_REJECT_ICMP_UNREACH;
    uint8_t code = NFT_REJECT_ICMP_UNREACH;
    size_t n = split_count(parms, ' ');
    if (n > 1) {
        char what[64], how[64];
        split_at(parms, ' ', 1, what, sizeof(what));
        split_at(parms, ' ', n - 1, how, sizeof(how));
        if (strcmp(what, "tcp") == 0) {
            type = NFT_REJECT_TCP_RST;
            code = NFT_REJECT_TCP_RST;
        } else if (strcmp(what, NFT_PROTO_ICMP) == 0) {
            type = NFT_REJECT_ICMP_UNREACH;
            if (strcmp(how, "host-unreachable") == 0 || strcmp(how, "addr-unreachable") == 0)
                code = 1;
            else if (strcmp(how, "prot-unreachable") == 0)
                code = 2;
            else if (strcmp(how, "port-unreachable") == 0)
                code = 3;
            else if (strcmp(how, "admin-prohibited") == 0)
                code = 13;
            else if (strcmp(how, "host-prohibited") == 0)
                code = 10;
            else if (strcmp(how, "net-prohibited") == 0)
                code = 9;
            else
                code = 0;
        } else if (strcmp(what, NFT_PROTO_ICMPX) == 0) {
            type = NFT_REJECT_ICMPX_UNREACH;
            if (strcmp(how, "prot-unreachable") == 0)
                code = NFT_REJECT_ICMPX_HOST_UNREACH;
            else if (strcmp(how, "port-unreachable") == 0)
                code = NFT_REJECT_ICMPX_PORT_UNREACH;
            else
                code = NFT_REJECT_ICMP_UNREACH; /* also no-route, net/host-unreachable */
        } else if (strcmp(what, NFT_PROTO_ICMPV6) == 0) {
            type = 1; /* sic: NFT_REJECT_TCP_RST */
            if (strcmp(how, "addr-unreachable") == 0)
                code = 3;
            else if (strcmp(how, "port-unreachable") == 0)
                code = 4;
            else if (strcmp(how, "policy-fail") == 0)
                code = 5;
            else if (strcmp(how, "reject-route") == 0)
                code = 6;
            else
                code = 0;
        }
    }
    struct nftnl_expr *e = ex("reject");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_REJECT_TYPE, type);
    nftnl_expr_set_u8(e, NFTNL_EXPR_REJECT_CODE, code);
    return ADD(r, e);
}

static bool lower_eq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a >= 'A' && *a <= 'Z' ? (char)(*a - 'A' + 'a') : *a;
        if (x != *b)
            return false;
    }
    return *a == *b;
}

/* NewExprVerdict */
bool ks_nftp_add_verdict(struct nftnl_rule *r, const char *target, const char *parms)
{
    bool ra, rp;
    struct nftnl_expr *e;
    if (lower_eq(target, "accept"))
        return e_verdict(r, VERDICT_ACCEPT, NULL);
    if (lower_eq(target, "drop"))
        return e_verdict(r, VERDICT_DROP, NULL);
    if (lower_eq(target, "stop"))
        return e_verdict(r, VERDICT_STOP, NULL);
    if (lower_eq(target, "reject"))
        return e_reject(r, parms);
    if (lower_eq(target, "return"))
        return e_verdict(r, VERDICT_RETURN, NULL);
    if (lower_eq(target, "jump"))
        return e_verdict(r, VERDICT_JUMP, parms);
    if (lower_eq(target, "queue")) {
        long long num = 0;
        char first[64], last[64];
        size_t n = split_count(parms, ' ');
        split_at(parms, ' ', 0, first, sizeof(first));
        split_at(parms, ' ', n - 1, last, sizeof(last));
        if (strcmp(first, "num") == 0 && !go_atoi(last, &num)) {
            ks_warning("invalid Queue num: %s", last);
            return false;
        }
        if ((e = ex("queue")) == NULL)
            return false;
        nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_NUM, (uint16_t)num);
        nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_TOTAL, 1);
        nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_FLAGS, NFT_QUEUE_FLAG_BYPASS);
        return ADD(r, e);
    }
    if (lower_eq(target, "snat") || lower_eq(target, "dnat")) {
        bool snat = lower_eq(target, "snat");
        if (!new_nat(r, parms, snat ? "snat" : "dnat", &ra, &rp))
            return false;
        return e_nat(r, snat ? NFT_NAT_SNAT : NFT_NAT_DNAT, ra, rp, nat_flags(parms));
    }
    if (lower_eq(target, "masquerade")) {
        uint32_t flags = nat_flags(parms);
        if ((e = ex("masq")) == NULL)
            return false;
        if (parms[0] == '\0') {
            if (flags != 0)
                nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_FLAGS, flags);
            return ADD(r, e);
        }
        /* with any flag set, the port isn't used */
        bool to_ports = flags == 0;
        if (to_ports)
            nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_REG_PROTO_MIN, NFT_REG_1);
        else
            nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_FLAGS, flags);
        new_nat(r, parms, "masquerade", &ra, &rp); /* errors only logged */
        return ADD(r, e);
    }
    if (lower_eq(target, "redirect")) {
        if (!new_nat(r, parms, "redirect", &ra, &rp))
            return false;
        if ((e = ex("redir")) == NULL)
            return false;
        nftnl_expr_set_u32(e, NFTNL_EXPR_REDIR_REG_PROTO_MIN, NFT_REG_1);
        return ADD(r, e);
    }
    if (lower_eq(target, "tproxy")) {
        if (!new_nat(r, parms, "tproxy", &ra, &rp))
            return false;
        if ((e = ex("tproxy")) == NULL)
            return false;
        nftnl_expr_set_u32(e, NFTNL_EXPR_TPROXY_FAMILY, NFPROTO_IPV4);
        nftnl_expr_set_u32(e, NFTNL_EXPR_TPROXY_REG_PORT, NFT_REG_1);
        return ADD(r, e) && e_verdict(r, VERDICT_ACCEPT, NULL);
    }
    /* the target can be empty ("ct set mark", "log"...) */
    return true;
}
