/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/netlink/socket.go and socket_linux.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/sockdiag.h"

#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/log.h"

/* TCP_ALL from upstream: every state bit, plus 0x2001. */
#define TCP_ALL (1u << 1 | 1u << 2 | 1u << 3 | 1u << 4 | 1u << 5 | 1u << 6 | \
                 1u << 7 | 1u << 8 | 1u << 9 | 1u << 10 | 1u << 11 | 1u << 12 | \
                 0x2001u)

static void to_ip(uint8_t family, const uint32_t raw[4], struct ks_ip *ip)
{
    const uint8_t *b = (const uint8_t *)raw;
    if (family == AF_INET6) {
        memcpy(ip->b, b, 16);
        ip->len = 16;
    } else {
        *ip = ks_ip_v4_16(b[0], b[1], b[2], b[3]); /* net.IPv4() */
    }
}

/* netlinkRequest: one NLM_F_DUMP request and all its replies. */
static int request(uint8_t family, uint8_t proto, uint16_t sport,
                   struct ks_sock **out, size_t *n, char *err, size_t errlen)
{
    *out = NULL;
    *n = 0;
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        snprintf(err, errlen, "socket: %s", strerror(errno));
        return -1;
    }

    struct {
        struct nlmsghdr nh;
        struct inet_diag_req_v2 r;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = sizeof(req);
    req.nh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;
    req.r.sdiag_family = family;
    req.r.sdiag_protocol = proto;
    req.r.idiag_states = TCP_ALL;
    req.r.id.idiag_sport = htons(sport);
    req.r.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    req.r.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        snprintf(err, errlen, "sendto: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int ret = 0;
    size_t cap = 0;
    union {
        struct nlmsghdr nh; /* alignment */
        char buf[32768];
    } u;
    for (bool done = false; !done;) {
        ssize_t len = recv(fd, u.buf, sizeof(u.buf), 0);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            snprintf(err, errlen, "recv: %s", strerror(errno));
            ret = -1;
            break;
        }
        if (len == 0)
            break;
        for (struct nlmsghdr *nh = &u.nh; NLMSG_OK(nh, (size_t)len);
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e = NLMSG_DATA(nh);
                if (nh->nlmsg_len >= NLMSG_LENGTH(sizeof(*e)) && e->error != 0) {
                    snprintf(err, errlen, "%s", strerror(-e->error));
                    ret = -1;
                }
                done = true;
                break;
            }
            if (nh->nlmsg_type != SOCK_DIAG_BY_FAMILY)
                continue;
            if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
                ks_error("netlink socket error: socket data short read (%u)",
                         nh->nlmsg_len);
                continue;
            }
            const struct inet_diag_msg *m = NLMSG_DATA(nh);
            if (*n == cap) {
                cap = cap ? cap * 2 : 16;
                struct ks_sock *ns = realloc(*out, cap * sizeof(*ns));
                if (ns == NULL) {
                    snprintf(err, errlen, "out of memory");
                    ret = -1;
                    done = true;
                    break;
                }
                *out = ns;
            }
            struct ks_sock *s = &(*out)[(*n)++];
            memset(s, 0, sizeof(*s));
            s->family = m->idiag_family;
            s->state = m->idiag_state;
            s->timer = m->idiag_timer;
            s->retrans = m->idiag_retrans;
            s->sport = ntohs(m->id.idiag_sport);
            s->dport = ntohs(m->id.idiag_dport);
            to_ip(s->family, m->id.idiag_src, &s->src);
            to_ip(s->family, m->id.idiag_dst, &s->dst);
            s->iface = m->id.idiag_if;
            s->cookie[0] = m->id.idiag_cookie[0];
            s->cookie[1] = m->id.idiag_cookie[1];
            s->expires = m->idiag_expires;
            s->rqueue = m->idiag_rqueue;
            s->wqueue = m->idiag_wqueue;
            s->uid = m->idiag_uid;
            s->inode = m->idiag_inode;
        }
    }
    close(fd);

    if (ret == 0 && *n == 0) {
        snprintf(err, errlen,
                 "Warning, no message nor error from netlink, or no connections found");
        ret = -1;
    }
    if (ret < 0) {
        free(*out);
        *out = NULL;
        *n = 0;
    }
    return ret;
}

int ks_sock_get(uint8_t family, uint8_t proto, uint16_t sport,
                struct ks_sock **out, size_t *n, char *err, size_t errlen)
{
    return request(family, proto, sport, out, n, err, errlen);
}

int ks_sock_dump(uint8_t family, uint8_t proto, struct ks_sock **out,
                 size_t *n, char *err, size_t errlen)
{
    return request(family, proto, 0, out, n, err, errlen);
}

/* inodes = append([]int{inode}, inodes...) */
static void prepend(int64_t *inodes, size_t *count, size_t max, int64_t inode)
{
    size_t keep = *count < max ? *count : (max ? max - 1 : 0);
    if (max == 0)
        return;
    memmove(inodes + 1, inodes, keep * sizeof(*inodes));
    inodes[0] = inode;
    *count = keep + 1;
}

size_t ks_socket_info(const char *proto, const struct ks_ip *src_ip,
                      unsigned src_port, const struct ks_ip *dst_ip,
                      unsigned dst_port, int64_t *uid, int64_t *inodes,
                      size_t max)
{
    size_t count = 0;
    size_t plen = strlen(proto);
    uint8_t family = AF_INET, ipproto = IPPROTO_TCP;

    *uid = -1;
    if (plen > 0 && proto[plen - 1] == '6')
        family = AF_INET6;
    if (strncmp(proto, "udp", 3) == 0) {
        ipproto = IPPROTO_UDP;
        if (strncmp(proto, "udplite", 7) == 0)
            ipproto = IPPROTO_UDPLITE;
    }
    if (strncmp(proto, "sctp", 4) == 0)
        ipproto = IPPROTO_SCTP;
    if (strncmp(proto, "icmp", 4) == 0)
        ipproto = IPPROTO_RAW;

    struct ks_sock *socks;
    size_t n;
    char err[256];
    if (ks_sock_get(family, ipproto, (uint16_t)src_port, &socks, &n, err,
                    sizeof(err)) < 0) {
        ks_debug("netlink socket error: %s - %u -> %u", err, src_port, dst_port);
        return 0;
    }

    for (size_t i = 0; i < n; i++) {
        const struct ks_sock *s = &socks[i];
        if (s->uid != 0xffffffffu)
            *uid = s->uid; /* the last socket's, as upstream */
        if (s->sport == (uint16_t)src_port && ks_ip_equal(&s->src, src_ip) &&
            s->dport == (uint16_t)dst_port &&
            (ks_ip_is_global_unicast(&s->dst) || ks_ip_is_loopback(&s->dst)) &&
            ks_ip_equal(&s->dst, dst_ip)) {
            prepend(inodes, &count, max, s->inode);
            continue;
        }
        ks_debug("GetSocketInfo() invalid: %u -> %u, inode %u", s->sport,
                 s->dport, s->inode);
    }

    /* Special cases: NTP queries (123), broadcasts, incoming connections. */
    if (count == 0) {
        struct ks_ip v4zero = ks_ip_v4_16(0, 0, 0, 0);
        struct ks_ip v6zero;
        memset(&v6zero, 0, sizeof(v6zero));
        v6zero.len = 16;
        for (size_t i = 0; i < n; i++) {
            const struct ks_sock *s = &socks[i];
            if (ks_ip_equal(&s->dst, &v4zero) || ks_ip_equal(&s->dst, &v6zero))
                prepend(inodes, &count, max, s->inode);
            else if (s->sport == (uint16_t)src_port && ks_ip_equal(&s->src, src_ip) &&
                     s->dport == (uint16_t)dst_port)
                prepend(inodes, &count, max, s->inode);
        }
    }
    free(socks);
    return count;
}

int ks_sock_find_by_inode(uint32_t inode, struct ks_sock *out)
{
    static const struct {
        uint8_t family, proto;
    } types[] = {
        {AF_INET, IPPROTO_TCP},
        {AF_INET, IPPROTO_UDP},
        {AF_INET6, IPPROTO_TCP},
        {AF_INET6, IPPROTO_UDP},
    };
    char err[256];
    for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        struct ks_sock *socks;
        size_t n;
        /* Upstream gives up on the first dump error. */
        if (ks_sock_dump(types[t].family, types[t].proto, &socks, &n, err,
                         sizeof(err)) < 0)
            return -1;
        for (size_t i = 0; i < n; i++) {
            if (socks[i].inode == inode) {
                *out = socks[i];
                free(socks);
                return 0;
            }
        }
        free(socks);
    }
    return -1;
}

/* Sends one request expecting an ACK (nl.NetlinkRequest.Execute with
 * NLM_F_ACK). Returns 0, or -1 with `err` filled. */
static int ack_request(int nl_proto, void *msg, size_t len, char *err, size_t errlen)
{
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, nl_proto);
    if (fd < 0) {
        snprintf(err, errlen, "socket: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, msg, len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        snprintf(err, errlen, "sendto: %s", strerror(errno));
        close(fd);
        return -1;
    }
    union {
        struct nlmsghdr nh;
        char buf[4096];
    } u;
    int ret = -1;
    snprintf(err, errlen, "no reply from netlink");
    for (;;) {
        ssize_t n = recv(fd, u.buf, sizeof(u.buf), 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            snprintf(err, errlen, "recv: %s", strerror(errno));
            break;
        }
        if (!NLMSG_OK(&u.nh, (size_t)n))
            break;
        if (u.nh.nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *e = NLMSG_DATA(&u.nh);
            if (u.nh.nlmsg_len < NLMSG_LENGTH(sizeof(*e)))
                break;
            if (e->error == 0)
                ret = 0;
            else
                snprintf(err, errlen, "%s", strerror(-e->error));
            break;
        }
        /* anything else: keep reading until the ACK */
    }
    close(fd);
    return ret;
}

/* SocketKill: SOCK_DESTROY for the socket `s` (needs
 * CONFIG_INET_DIAG_DESTROY and CAP_NET_ADMIN). */
static int sock_kill(uint8_t family, uint8_t proto, const struct ks_sock *s,
                     char *err, size_t errlen)
{
    struct {
        struct nlmsghdr nh;
        struct inet_diag_req_v2 r;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = sizeof(req);
    req.nh.nlmsg_type = SOCK_DESTROY;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_seq = 1;
    req.r.sdiag_family = family;
    req.r.sdiag_protocol = proto;
    req.r.id.idiag_sport = htons(s->sport);
    req.r.id.idiag_dport = htons(s->dport);
    /* SocketRequest.Serialize: 4 bytes for IPv4, 16 for IPv6. */
    if (family == AF_INET6) {
        memcpy(req.r.id.idiag_src, s->src.b, 16);
        memcpy(req.r.id.idiag_dst, s->dst.b, 16);
    } else {
        ks_ip_to4(&s->src, (uint8_t *)req.r.id.idiag_src);
        ks_ip_to4(&s->dst, (uint8_t *)req.r.id.idiag_dst);
    }
    req.r.id.idiag_if = s->iface;
    req.r.id.idiag_cookie[0] = s->cookie[0];
    req.r.id.idiag_cookie[1] = s->cookie[1];
    return ack_request(NETLINK_SOCK_DIAG, &req, sizeof(req), err, errlen);
}

/* proto string -> family and IPPROTO_*, as KillSocket parses it. */
static void proto_family(const char *proto, uint8_t *family, uint8_t *ipproto)
{
    size_t plen = strlen(proto);
    *family = plen > 0 && proto[plen - 1] == '6' ? AF_INET6 : AF_INET;
    *ipproto = IPPROTO_TCP;
    if (strncmp(proto, "udp", 3) == 0)
        *ipproto = strncmp(proto, "udplite", 7) == 0 ? IPPROTO_UDPLITE : IPPROTO_UDP;
}

void ks_kill_socket(const char *proto, const struct ks_ip *src_ip,
                    unsigned src_port, const struct ks_ip *dst_ip,
                    unsigned dst_port)
{
    (void)src_ip;
    (void)dst_ip;
    uint8_t family, ipproto;
    proto_family(proto, &family, &ipproto);

    char err[256];
    struct ks_sock *socks;
    size_t n;
    if (ks_sock_get(family, ipproto, (uint16_t)src_port, &socks, &n, err,
                    sizeof(err)) < 0)
        return;
    /* Every socket with this source port, as upstream. */
    for (size_t i = 0; i < n; i++)
        if (sock_kill(family, ipproto, &socks[i], err, sizeof(err)) < 0)
            ks_debug("Unable to kill socket: %u, %u, %s", src_port, dst_port, err);
    free(socks);
}

/* netlink/ifaces.go isPrivate */
static bool is_private(const struct ks_ip *ip)
{
    uint8_t b[4];
    if (ks_ip_to4(ip, b))
        return b[0] == 10 || (b[0] == 172 && (b[1] & 0xf0) == 16) ||
               (b[0] == 192 && b[1] == 168);
    return ip->len == 16 && (ip->b[0] & 0xfe) == 0xfc;
}

int ks_kill_sockets(uint8_t family, uint8_t proto, bool exclude_local,
                    char *err, size_t errlen)
{
    struct ks_sock *socks;
    size_t n;
    if (ks_sock_dump(family, proto, &socks, &n, err, errlen) < 0) {
        char e[256];
        snprintf(e, sizeof(e), "%s", err);
        snprintf(err, errlen, "eBPF could not dump TCP (%u/%u) sockets via netlink: %s",
                 family, proto, e);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        const struct ks_sock *s = &socks[i];
        char kerr[256];
        if (exclude_local && (is_private(&s->dst) || ks_ip_is_unspecified(&s->src) ||
                              ks_ip_is_unspecified(&s->dst))) {
            ks_trace("not killing socket: %u -> %u", s->sport, s->dport);
            continue;
        }
        ks_trace("killing socket: %u -> %u", s->sport, s->dport);
        if (sock_kill(family, proto, s, kerr, sizeof(kerr)) < 0)
            ks_trace("Unable to kill socket (%u -> %u): %s", s->sport,
                   s->dport, kerr);
    }
    free(socks);
    return 0;
}

void ks_kill_all_sockets(void)
{
    static const struct {
        uint8_t family, proto;
    } opts[] = {
        {AF_INET, IPPROTO_TCP},  {AF_INET6, IPPROTO_TCP},
        {AF_INET, IPPROTO_UDP},  {AF_INET6, IPPROTO_UDP},
        {AF_INET, IPPROTO_SCTP}, {AF_INET6, IPPROTO_SCTP},
    };
    char err[512];
    for (size_t i = 0; i < sizeof(opts) / sizeof(opts[0]); i++)
        (void)ks_kill_sockets(opts[i].family, opts[i].proto, true, err, sizeof(err));
}

/* vishvananda/netlink ConntrackTableFlush: an IPCTNL_MSG_CT_DELETE without
 * a tuple, which the kernel takes as "flush everything" (nfgen version 0
 * means any family). */
static int conntrack_flush(uint8_t subsys, char *err, size_t errlen)
{
    struct {
        struct nlmsghdr nh;
        struct nfgenmsg g;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = sizeof(req);
    req.nh.nlmsg_type = (uint16_t)(subsys << 8 | IPCTNL_MSG_CT_DELETE);
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_seq = 1;
    req.g.nfgen_family = AF_INET;
    req.g.version = NFNETLINK_V0;
    return ack_request(NETLINK_NETFILTER, &req, sizeof(req), err, errlen);
}

void ks_conntrack_flush_table(void)
{
    char err[256];
    if (conntrack_flush(NFNL_SUBSYS_CTNETLINK, err, sizeof(err)) < 0)
        ks_error("error in ConntrackTableFlush %s", err);
}

void ks_flush_connections(void)
{
    char err[256];
    if (conntrack_flush(NFNL_SUBSYS_CTNETLINK, err, sizeof(err)) < 0)
        ks_error("error flushing ConntrackTable %s", err);
    if (conntrack_flush(NFNL_SUBSYS_CTNETLINK_EXP, err, sizeof(err)) < 0)
        ks_error("error flusing ConntrackExpectTable %s", err);
    /* Force established connections to reestablish again. */
    ks_kill_all_sockets();
}
