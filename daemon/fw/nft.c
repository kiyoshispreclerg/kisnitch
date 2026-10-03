/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/firewall/nftables/{nftables,tables,chains,rules,
 * monitor,utils}.go (interception) and the rules checker of
 * daemon/firewall/common/common.go.
 *
 * google/nftables queues messages and sends them on Flush() (our commit());
 * we do the same with an nfnetlink batch. Function names follow upstream's.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/fw/nft.h"

/* glibc's netinet/in.h must come before the kernel headers */
#include <netinet/in.h>

#include <errno.h>
#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/common.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/table.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "common/duration.h"
#include "common/log.h"
#include "daemon/evloop.h"

#define LOG_TAG "nftables:"
#define NAME_LEN 256 /* NFT_NAME_MAXLEN */

/* google/nftables chain priorities and types. */
#define PRIO_MANGLE (-150)
#define PRIO_FILTER 0
#define TYPE_FILTER "filter"
#define TYPE_ROUTE "route"

/* ct state bits (expr.CtStateBit*) */
#define CT_STATE_NEW 8u
#define CT_STATE_RELATED 4u

#define BATCH_BUF_SIZE (64 * 1024)
/* Big enough for any rule other programs may have added. */
#define RECV_BUF_SIZE (64 * 1024)
/* A dump request (MNL_SOCKET_BUFFER_SIZE is not a constant expression). */
#define REQ_BUF_SIZE 1024
/* ReloadRulesCallback sleeps this long between deleting and re-adding. */
#define RELOAD_DELAY_NS (500 * KS_MILLISECOND)

/* nftables.Chain, as listed from the kernel or as we add it. */
struct chain {
    char name[NAME_LEN];
    char table[NAME_LEN];
    uint8_t family;
    bool has_hook;
    uint32_t hooknum;
    int32_t prio;
    char type[16];
    bool has_policy;
    uint32_t policy;
};

struct rule {
    uint64_t handle;
    uint8_t *udata;
    size_t udata_len;
};

/* sysTables entry: key "name-family". */
struct table_entry {
    char name[NAME_LEN];
    char family[16];
    uint8_t fam;
};

/* sysChains entry: key from chain_key(). */
struct chain_entry {
    char key[NAME_LEN * 2 + 16];
    struct chain c;
};

struct ks_nft {
    struct ks_evloop *loop;
    struct mnl_socket *nl;
    uint32_t portid;
    uint32_t seq;

    char *buf;   /* the batch */
    char *rbuf;  /* replies */
    struct mnl_nlmsg_batch *batch;
    size_t nmsgs;
    bool batch_full;

    struct table_entry *tables;
    size_t ntables;
    struct chain_entry *chains;
    size_t nchains;

    uint16_t queue_num;
    bool bypass_queue;
    char *config_path;
    int64_t check_interval;
    bool running;
    struct ks_timer *checker;
    struct ks_timer *reload_timer;
};

/* ---- netlink -------------------------------------------------------- */

static bool conn_open(struct ks_nft *n)
{
    if (n->nl != NULL)
        return true;
    n->nl = mnl_socket_open2(NETLINK_NETFILTER, SOCK_CLOEXEC);
    if (n->nl == NULL || mnl_socket_bind(n->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        ks_error("%s unable to open the netlink socket: %s", LOG_TAG, strerror(errno));
        if (n->nl != NULL)
            mnl_socket_close(n->nl);
        n->nl = NULL;
        return false;
    }
    n->portid = mnl_socket_get_portid(n->nl);
    return true;
}

static void conn_close(struct ks_nft *n)
{
    if (n->nl != NULL)
        mnl_socket_close(n->nl);
    n->nl = NULL;
}

/* Room for the next message of the batch (opening it if needed), or NULL
 * if it's full (then commit() fails). */
static char *batch_room(struct ks_nft *n)
{
    if (n->batch_full)
        return NULL;
    if (n->nmsgs == 0 && mnl_nlmsg_batch_is_empty(n->batch)) {
        nftnl_batch_begin(mnl_nlmsg_batch_current(n->batch), n->seq++);
        mnl_nlmsg_batch_next(n->batch);
    }
    /* Each message we build is far smaller than this. */
    if (mnl_nlmsg_batch_size(n->batch) + 4096 > BATCH_BUF_SIZE) {
        n->batch_full = true;
        return NULL;
    }
    return mnl_nlmsg_batch_current(n->batch);
}

static void batch_added(struct ks_nft *n)
{
    mnl_nlmsg_batch_next(n->batch);
    n->nmsgs++;
}

static void batch_reset(struct ks_nft *n)
{
    mnl_nlmsg_batch_reset(n->batch);
    n->nmsgs = 0;
    n->batch_full = false;
}

/* Reads every reply already queued on the socket (the kernel answers a
 * batch while processing the send). Returns 0 or a negative errno. With
 * `discard`, just empties the socket (leftovers of an interrupted dump). */
static int read_acks(struct ks_nft *n, bool discard)
{
    int err = 0;
    for (;;) {
        ssize_t len = recv(mnl_socket_get_fd(n->nl), n->rbuf, RECV_BUF_SIZE, MSG_DONTWAIT);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK && err == 0)
                err = -errno;
            break;
        }
        if (!discard && mnl_cb_run(n->rbuf, (size_t)len, 0, n->portid, NULL, NULL) < 0 &&
            err == 0)
            err = -errno;
    }
    return err;
}

/* Conn.Flush(), Nft.Commit(): sends the queued messages. Nothing queued is
 * a success. */
static bool commit(struct ks_nft *n)
{
    if (n->nmsgs == 0) {
        batch_reset(n);
        return true;
    }
    int err = 0;
    if (n->batch_full) {
        err = -ENOBUFS;
    } else if (n->nl == NULL) {
        err = -ENOTCONN;
    } else {
        nftnl_batch_end(mnl_nlmsg_batch_current(n->batch), n->seq++);
        mnl_nlmsg_batch_next(n->batch);
        read_acks(n, true);
        if (mnl_socket_sendto(n->nl, mnl_nlmsg_batch_head(n->batch),
                              mnl_nlmsg_batch_size(n->batch)) < 0)
            err = -errno;
        else
            err = read_acks(n, false);
    }
    batch_reset(n);
    if (err != 0) {
        ks_warning("%s error applying changes: %s", LOG_TAG, strerror(-err));
        return false;
    }
    return true;
}

typedef int (*dump_cb)(const struct nlmsghdr *nlh, void *data);

/* A dump request; `cb` is called for each object. 0 or -1. */
static int dump(struct ks_nft *n, struct nlmsghdr *nlh, dump_cb cb, void *data)
{
    if (n->nl == NULL) {
        errno = ENOTCONN;
        return -1;
    }
    uint32_t seq = nlh->nlmsg_seq;
    read_acks(n, true);
    if (mnl_socket_sendto(n->nl, nlh, nlh->nlmsg_len) < 0)
        return -1;
    for (;;) {
        ssize_t len = mnl_socket_recvfrom(n->nl, n->rbuf, RECV_BUF_SIZE);
        if (len < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        int ret = mnl_cb_run(n->rbuf, (size_t)len, seq, n->portid, cb, data);
        if (ret < 0)
            return -1;
        if (ret == MNL_CB_STOP)
            return 0;
    }
}

struct chain_list {
    struct chain *v;
    size_t n, cap;
    bool oom;
};

static int chain_cb(const struct nlmsghdr *nlh, void *data)
{
    struct chain_list *l = data;
    struct nftnl_chain *c = nftnl_chain_alloc();
    if (c == NULL) {
        l->oom = true;
        return MNL_CB_OK;
    }
    if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
        goto out;
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 16;
        struct chain *v = realloc(l->v, cap * sizeof(*v));
        if (v == NULL) {
            l->oom = true;
            goto out;
        }
        l->v = v;
        l->cap = cap;
    }
    struct chain *ch = &l->v[l->n++];
    memset(ch, 0, sizeof(*ch));
    snprintf(ch->name, sizeof(ch->name), "%s", nftnl_chain_get_str(c, NFTNL_CHAIN_NAME));
    snprintf(ch->table, sizeof(ch->table), "%s", nftnl_chain_get_str(c, NFTNL_CHAIN_TABLE));
    ch->family = (uint8_t)nftnl_chain_get_u32(c, NFTNL_CHAIN_FAMILY);
    if (nftnl_chain_is_set(c, NFTNL_CHAIN_HOOKNUM)) {
        ch->has_hook = true;
        ch->hooknum = nftnl_chain_get_u32(c, NFTNL_CHAIN_HOOKNUM);
        ch->prio = nftnl_chain_get_s32(c, NFTNL_CHAIN_PRIO);
    }
    if (nftnl_chain_is_set(c, NFTNL_CHAIN_TYPE))
        snprintf(ch->type, sizeof(ch->type), "%s", nftnl_chain_get_str(c, NFTNL_CHAIN_TYPE));
    if (nftnl_chain_is_set(c, NFTNL_CHAIN_POLICY)) {
        ch->has_policy = true;
        ch->policy = nftnl_chain_get_u32(c, NFTNL_CHAIN_POLICY);
    }
out:
    nftnl_chain_free(c);
    return MNL_CB_OK;
}

/* Conn.ListChains(): every chain of every family. Caller frees *out. */
static int list_chains(struct ks_nft *n, struct chain **out, size_t *count)
{
    char buf[REQ_BUF_SIZE];
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, NFPROTO_UNSPEC,
                                                 NLM_F_DUMP | NLM_F_ACK, n->seq++);
    struct chain_list l = {0};
    int ret = dump(n, nlh, chain_cb, &l);
    if (ret == 0 && l.oom) {
        errno = ENOMEM;
        ret = -1;
    }
    if (ret < 0) {
        free(l.v);
        return -1;
    }
    *out = l.v;
    *count = l.n;
    return 0;
}

struct rule_list {
    struct rule *v;
    size_t n, cap;
    bool oom;
};

static int rule_cb(const struct nlmsghdr *nlh, void *data)
{
    struct rule_list *l = data;
    struct nftnl_rule *r = nftnl_rule_alloc();
    if (r == NULL) {
        l->oom = true;
        return MNL_CB_OK;
    }
    if (nftnl_rule_nlmsg_parse(nlh, r) < 0)
        goto out;
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 8;
        struct rule *v = realloc(l->v, cap * sizeof(*v));
        if (v == NULL) {
            l->oom = true;
            goto out;
        }
        l->v = v;
        l->cap = cap;
    }
    struct rule *ru = &l->v[l->n];
    memset(ru, 0, sizeof(*ru));
    ru->handle = nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE);
    if (nftnl_rule_is_set(r, NFTNL_RULE_USERDATA)) {
        uint32_t len = 0;
        const void *ud = nftnl_rule_get_data(r, NFTNL_RULE_USERDATA, &len);
        ru->udata = malloc(len ? len : 1);
        if (ru->udata == NULL) {
            l->oom = true;
            goto out;
        }
        memcpy(ru->udata, ud, len);
        ru->udata_len = len;
    }
    l->n++;
out:
    nftnl_rule_free(r);
    return MNL_CB_OK;
}

static void free_rules(struct rule *v, size_t count)
{
    for (size_t i = 0; i < count; i++)
        free(v[i].udata);
    free(v);
}

/* Conn.GetRule(table, chain) */
static int get_rules(struct ks_nft *n, const struct chain *c, struct rule **out,
                     size_t *count)
{
    char buf[REQ_BUF_SIZE];
    struct nftnl_rule *r = nftnl_rule_alloc();
    if (r == NULL) {
        errno = ENOMEM;
        return -1;
    }
    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, c->table);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, c->name);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, c->family,
                                                 NLM_F_DUMP | NLM_F_ACK, n->seq++);
    nftnl_rule_nlmsg_build_payload(nlh, r);
    nftnl_rule_free(r);

    struct rule_list l = {0};
    int ret = dump(n, nlh, rule_cb, &l);
    if (ret == 0 && l.oom) {
        errno = ENOMEM;
        ret = -1;
    }
    if (ret < 0) {
        free_rules(l.v, l.n);
        return -1;
    }
    *out = l.v;
    *count = l.n;
    return 0;
}

static bool rule_has_key(const struct rule *r, const char *key)
{
    size_t klen = strlen(key);
    return r->udata != NULL && r->udata_len == klen && memcmp(r->udata, key, klen) == 0;
}

/* ---- message builders --------------------------------------------- */

static void queue_new_table(struct ks_nft *n, const char *name, uint8_t fam)
{
    char *room = batch_room(n);
    struct nftnl_table *t = nftnl_table_alloc();
    if (room == NULL || t == NULL) {
        n->batch_full = true;
        nftnl_table_free(t);
        return;
    }
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, name);
    nftnl_table_set_u32(t, NFTNL_TABLE_FLAGS, 0);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_NEWTABLE, fam,
                                                 NLM_F_CREATE | NLM_F_ACK, n->seq++);
    nftnl_table_nlmsg_build_payload(nlh, t);
    nftnl_table_free(t);
    batch_added(n);
}

static void queue_del_table(struct ks_nft *n, const char *name, uint8_t fam)
{
    char *room = batch_room(n);
    struct nftnl_table *t = nftnl_table_alloc();
    if (room == NULL || t == NULL) {
        n->batch_full = true;
        nftnl_table_free(t);
        return;
    }
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, name);
    nftnl_table_set_u32(t, NFTNL_TABLE_FLAGS, 0);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_DELTABLE, fam,
                                                 NLM_F_ACK, n->seq++);
    nftnl_table_nlmsg_build_payload(nlh, t);
    nftnl_table_free(t);
    batch_added(n);
}

/* Conn.AddChain: hook and priority only if both are set. */
static void queue_new_chain(struct ks_nft *n, const struct chain *c)
{
    char *room = batch_room(n);
    struct nftnl_chain *ch = nftnl_chain_alloc();
    if (room == NULL || ch == NULL) {
        n->batch_full = true;
        nftnl_chain_free(ch);
        return;
    }
    nftnl_chain_set_str(ch, NFTNL_CHAIN_TABLE, c->table);
    nftnl_chain_set_str(ch, NFTNL_CHAIN_NAME, c->name);
    if (c->has_hook) {
        nftnl_chain_set_u32(ch, NFTNL_CHAIN_HOOKNUM, c->hooknum);
        nftnl_chain_set_s32(ch, NFTNL_CHAIN_PRIO, c->prio);
    }
    if (c->has_policy)
        nftnl_chain_set_u32(ch, NFTNL_CHAIN_POLICY, c->policy);
    if (c->type[0] != '\0')
        nftnl_chain_set_str(ch, NFTNL_CHAIN_TYPE, c->type);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_NEWCHAIN, c->family,
                                                 NLM_F_CREATE | NLM_F_ACK, n->seq++);
    nftnl_chain_nlmsg_build_payload(nlh, ch);
    nftnl_chain_free(ch);
    batch_added(n);
}

static void queue_del_chain(struct ks_nft *n, const struct chain *c)
{
    char *room = batch_room(n);
    struct nftnl_chain *ch = nftnl_chain_alloc();
    if (room == NULL || ch == NULL) {
        n->batch_full = true;
        nftnl_chain_free(ch);
        return;
    }
    nftnl_chain_set_str(ch, NFTNL_CHAIN_TABLE, c->table);
    nftnl_chain_set_str(ch, NFTNL_CHAIN_NAME, c->name);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_DELCHAIN, c->family,
                                                 NLM_F_ACK, n->seq++);
    nftnl_chain_nlmsg_build_payload(nlh, ch);
    nftnl_chain_free(ch);
    batch_added(n);
}

static void queue_del_rule(struct ks_nft *n, const struct chain *c, uint64_t handle)
{
    char *room = batch_room(n);
    struct nftnl_rule *r = nftnl_rule_alloc();
    if (room == NULL || r == NULL) {
        n->batch_full = true;
        nftnl_rule_free(r);
        return;
    }
    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, c->table);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, c->name);
    nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, handle);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_DELRULE, c->family,
                                                 NLM_F_ACK, n->seq++);
    nftnl_rule_nlmsg_build_payload(nlh, r);
    nftnl_rule_free(r);
    batch_added(n);
}

/* Expressions, in google/nftables terms. Each returns false on OOM. */

static bool add_expr(struct nftnl_rule *r, struct nftnl_expr *e)
{
    if (e == NULL)
        return false;
    nftnl_rule_add_expr(r, e);
    return true;
}

/* expr.Meta{Key: MetaKeyL4PROTO, Register: 1} */
static bool e_meta_l4proto(struct nftnl_rule *r)
{
    struct nftnl_expr *e = nftnl_expr_alloc("meta");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, NFT_META_L4PROTO);
    nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, NFT_REG_1);
    return add_expr(r, e);
}

/* expr.Cmp{Op, Register: 1, Data} */
static bool e_cmp(struct nftnl_rule *r, enum nft_cmp_ops op, const void *data, uint32_t len)
{
    struct nftnl_expr *e = nftnl_expr_alloc("cmp");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
    nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, len);
    return add_expr(r, e);
}

/* expr.Payload{DestRegister: 1, Base: PayloadBaseTransportHeader, ...} */
static bool e_payload_th(struct nftnl_rule *r, uint32_t offset, uint32_t len)
{
    struct nftnl_expr *e = nftnl_expr_alloc("payload");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);
    return add_expr(r, e);
}

/* expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len, Mask, Xor} */
static bool e_bitwise(struct nftnl_rule *r, const void *mask, const void *xor, uint32_t len)
{
    struct nftnl_expr *e = nftnl_expr_alloc("bitwise");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
    nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
    nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_LEN, len);
    nftnl_expr_set(e, NFTNL_EXPR_BITWISE_MASK, mask, len);
    nftnl_expr_set(e, NFTNL_EXPR_BITWISE_XOR, xor, len);
    return add_expr(r, e);
}

/* expr.Ct{Register: 1, Key: CtKeySTATE} */
static bool e_ct_state(struct nftnl_rule *r)
{
    struct nftnl_expr *e = nftnl_expr_alloc("ct");
    if (e == NULL)
        return false;
    nftnl_expr_set_u32(e, NFTNL_EXPR_CT_KEY, NFT_CT_STATE);
    nftnl_expr_set_u32(e, NFTNL_EXPR_CT_DREG, NFT_REG_1);
    return add_expr(r, e);
}

/* expr.Queue{Num, Flag}; google/nftables sends Total = 1. */
static bool e_queue(struct ks_nft *n, struct nftnl_rule *r)
{
    struct nftnl_expr *e = nftnl_expr_alloc("queue");
    if (e == NULL)
        return false;
    nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_NUM, n->queue_num);
    nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_TOTAL, 1);
    /* getBypassFlag */
    nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_FLAGS, n->bypass_queue ? NFT_QUEUE_FLAG_BYPASS : 0);
    return add_expr(r, e);
}

enum rule_kind { RULE_DNS, RULE_NOT_TCP_NEW, RULE_TCP_SYN };

/* The expressions of each interception rule (rules.go). */
static bool build_rule_exprs(struct ks_nft *n, struct nftnl_rule *r, enum rule_kind kind)
{
    static const uint8_t udp = IPPROTO_UDP, tcp = IPPROTO_TCP;
    static const uint8_t port53[2] = {0, 53}; /* BigEndian.PutUint16(53) */
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    static const uint8_t syn_mask = 0x17, zero1 = 0, syn = 0x02;
    /* NativeEndian.PutUint32(CtStateBitNEW | CtStateBitRELATED) */
    uint32_t ct_mask = CT_STATE_NEW | CT_STATE_RELATED, ct_xor = 0;

    switch (kind) {
    case RULE_DNS: /* udp sport 53 */
        return e_meta_l4proto(r) && e_cmp(r, NFT_CMP_EQ, &udp, 1) &&
               e_payload_th(r, 0, 2) && e_cmp(r, NFT_CMP_EQ, port53, 2) && e_queue(n, r);
    case RULE_NOT_TCP_NEW: /* meta l4proto != tcp ct state new,related */
        return e_meta_l4proto(r) && e_cmp(r, NFT_CMP_NEQ, &tcp, 1) && e_ct_state(r) &&
               e_bitwise(r, &ct_mask, &ct_xor, 4) && e_cmp(r, NFT_CMP_NEQ, zero4, 4) &&
               e_queue(n, r);
    case RULE_TCP_SYN: /* tcp flags & (fin|syn|rst|ack) == syn */
        return e_meta_l4proto(r) && e_cmp(r, NFT_CMP_EQ, &tcp, 1) &&
               e_payload_th(r, 13, 1) && e_bitwise(r, &syn_mask, &zero1, 1) &&
               e_cmp(r, NFT_CMP_EQ, &syn, 1) && e_queue(n, r);
    }
    return false;
}

/* Conn.AddRule (append) / Conn.InsertRule (at the top), with the
 * interception key as user data. */
static void queue_new_rule(struct ks_nft *n, const struct chain *c, enum rule_kind kind,
                           bool append)
{
    char *room = batch_room(n);
    struct nftnl_rule *r = nftnl_rule_alloc();
    if (room == NULL || r == NULL) {
        n->batch_full = true;
        nftnl_rule_free(r);
        return;
    }
    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, c->table);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, c->name);
    nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, c->family);
    nftnl_rule_set_data(r, NFTNL_RULE_USERDATA, KS_NFT_INTERCEPTION_KEY,
                        (uint32_t)strlen(KS_NFT_INTERCEPTION_KEY));
    if (!build_rule_exprs(n, r, kind)) {
        n->batch_full = true;
        nftnl_rule_free(r);
        return;
    }
    uint16_t flags = NLM_F_CREATE | NLM_F_ACK | (append ? NLM_F_APPEND : 0);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_NEWRULE, c->family, flags,
                                                 n->seq++);
    nftnl_rule_nlmsg_build_payload(nlh, r);
    nftnl_rule_free(r);
    batch_added(n);
}

/* ---- stores (sysTables, sysChains) -------------------------------- */

/* GetFamilyCode */
static uint8_t family_code(const char *family)
{
    if (strcmp(family, "ip6") == 0)
        return NFPROTO_IPV6;
    if (strcmp(family, "ip") == 0)
        return NFPROTO_IPV4;
    if (strcmp(family, "bridge") == 0)
        return NFPROTO_BRIDGE;
    if (strcmp(family, "arp") == 0)
        return NFPROTO_ARP;
    if (strcmp(family, "netdev") == 0)
        return NFPROTO_NETDEV;
    return NFPROTO_INET;
}

/* getChainKey */
static void chain_key(const char *name, const char *table, uint8_t fam, char *buf,
                      size_t len)
{
    snprintf(buf, len, "%s-%s-%u", name, table, fam);
}

static struct table_entry *get_table(struct ks_nft *n, const char *name, const char *family)
{
    for (size_t i = 0; i < n->ntables; i++)
        if (strcmp(n->tables[i].name, name) == 0 && strcmp(n->tables[i].family, family) == 0)
            return &n->tables[i];
    return NULL;
}

static struct chain_entry *store_get_chain(struct ks_nft *n, const char *key)
{
    for (size_t i = 0; i < n->nchains; i++)
        if (strcmp(n->chains[i].key, key) == 0)
            return &n->chains[i];
    return NULL;
}

static void store_del_chain(struct ks_nft *n, const char *key)
{
    for (size_t i = 0; i < n->nchains; i++) {
        if (strcmp(n->chains[i].key, key) == 0) {
            n->chains[i] = n->chains[--n->nchains];
            return;
        }
    }
}

static void store_put_chain(struct ks_nft *n, const char *key, const struct chain *c)
{
    struct chain_entry *e = store_get_chain(n, key);
    if (e == NULL) {
        struct chain_entry *v = realloc(n->chains, (n->nchains + 1) * sizeof(*v));
        if (v == NULL) {
            ks_error("%s out of memory", LOG_TAG);
            return;
        }
        n->chains = v;
        e = &n->chains[n->nchains++];
        snprintf(e->key, sizeof(e->key), "%s", key);
    }
    e->c = *c;
}

/* InitMapsStore */
static void init_maps_store(struct ks_nft *n)
{
    free(n->tables);
    free(n->chains);
    n->tables = NULL;
    n->ntables = 0;
    n->chains = NULL;
    n->nchains = 0;
}

/* ---- tables.go ---------------------------------------------------- */

/* AddTable. Returns the stored table, or NULL with the error in `err`. */
static struct table_entry *add_table(struct ks_nft *n, const char *name, const char *family,
                                     char *err, size_t errlen)
{
    uint8_t fam = family_code(family);
    queue_new_table(n, name, fam);
    if (!commit(n)) {
        snprintf(err, errlen, "%s error adding system firewall table: %s, family: %s (%u)",
                 LOG_TAG, name, family, fam);
        return NULL;
    }
    struct table_entry *t = get_table(n, name, family);
    if (t == NULL) {
        struct table_entry *v = realloc(n->tables, (n->ntables + 1) * sizeof(*v));
        if (v == NULL) {
            snprintf(err, errlen, "out of memory");
            return NULL;
        }
        n->tables = v;
        t = &n->tables[n->ntables++];
    }
    snprintf(t->name, sizeof(t->name), "%s", name);
    snprintf(t->family, sizeof(t->family), "%s", family);
    t->fam = fam;
    return t;
}

/* AddInterceptionTables */
static int add_interception_tables(struct ks_nft *n, char *err, size_t errlen)
{
    return add_table(n, KS_NFT_TABLE_OPENSNITCH, KS_NFT_FAMILY_INET, err, errlen) ? 0 : -1;
}

/* nonSystemRules: rules in the chains of tables sharing the name *or* the
 * family with `t` (upstream's condition; see docs/UPSTREAM.md). -1 on
 * error. */
static long non_system_rules(struct ks_nft *n, const struct table_entry *t)
{
    struct chain *chains;
    size_t nchains;
    if (list_chains(n, &chains, &nchains) < 0)
        return -1;
    long total = 0;
    for (size_t i = 0; i < nchains; i++) {
        if (strcmp(t->name, chains[i].table) != 0 && t->fam != chains[i].family)
            continue;
        struct rule *rules;
        size_t nrules;
        if (get_rules(n, &chains[i], &rules, &nrules) < 0) {
            free(chains);
            return -1;
        }
        total += (long)nrules;
        free_rules(rules, nrules);
    }
    free(chains);
    return total;
}

/* DelSystemTables */
static void del_system_tables(struct ks_nft *n)
{
    for (size_t i = 0; i < n->ntables;) {
        struct table_entry *t = &n->tables[i];
        if (non_system_rules(n, t) != 0) {
            i++;
            continue;
        }
        queue_del_table(n, t->name, t->fam);
        if (!commit(n)) {
            ks_warning("error deleting system table: %s-%s", t->name, t->family);
            i++;
            continue;
        }
        n->tables[i] = n->tables[--n->ntables];
    }
}

/* ---- chains.go ---------------------------------------------------- */

/* Nft.GetChain: the chain in the kernel, if it exists. */
static bool kernel_get_chain(struct ks_nft *n, const char *name, const struct table_entry *t,
                             const char *family, struct chain *out)
{
    struct chain *chains;
    size_t nchains;
    bool found = false;
    if (list_chains(n, &chains, &nchains) < 0)
        return false;
    for (size_t i = 0; i < nchains && !found; i++) {
        if (strcmp(name, chains[i].name) == 0 && strcmp(t->name, chains[i].table) == 0 &&
            family_code(family) == chains[i].family) {
            *out = chains[i];
            found = true;
        }
    }
    free(chains);
    return found;
}

/* AddChain: queues the chain (the caller commits). Reuses the chain if it
 * already exists. Returns false if the table isn't known. */
static bool add_chain(struct ks_nft *n, const char *name, const char *table,
                      const char *family, int32_t prio, const char *type,
                      uint32_t hooknum, uint32_t policy)
{
    if (family[0] == '\0')
        family = KS_NFT_FAMILY_INET;
    struct table_entry *t = get_table(n, table, family);
    if (t == NULL) {
        ks_error("%s addChain, Error getting table: %s, %s", LOG_TAG, table, family);
        return false;
    }

    char key[sizeof(((struct chain_entry *)0)->key)];
    chain_key(name, t->name, t->fam, key, sizeof(key));
    struct chain c;
    if (kernel_get_chain(n, name, t, family, &c)) {
        store_del_chain(n, key);
        c.has_policy = true;
        c.policy = policy;
    } else {
        memset(&c, 0, sizeof(c));
        /* strings.ToLower(name): our names are ASCII */
        size_t i;
        for (i = 0; i < sizeof(c.name) - 1 && name[i] != '\0'; i++)
            c.name[i] = (char)(name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i]);
        c.name[i] = '\0';
        snprintf(c.table, sizeof(c.table), "%s", t->name);
        c.family = t->fam;
        snprintf(c.type, sizeof(c.type), "%s", type);
        c.has_hook = true;
        c.hooknum = hooknum;
        c.prio = prio;
        c.has_policy = true;
        c.policy = policy;
    }
    queue_new_chain(n, &c);
    store_put_chain(n, key, &c);
    return true;
}

/* The policy of a chain we added before, or accept. */
static uint32_t stored_policy(struct ks_nft *n, const char *name)
{
    struct table_entry *t = get_table(n, KS_NFT_TABLE_OPENSNITCH, KS_NFT_FAMILY_INET);
    if (t == NULL)
        return NF_ACCEPT;
    char key[sizeof(((struct chain_entry *)0)->key)];
    chain_key(name, t->name, t->fam, key, sizeof(key));
    struct chain_entry *e = store_get_chain(n, key);
    return e != NULL && e->c.has_policy ? e->c.policy : NF_ACCEPT;
}

/* AddInterceptionChains */
static int add_interception_chains(struct ks_nft *n)
{
    uint32_t filter_policy = stored_policy(n, KS_NFT_CHAIN_FILTER_INPUT);
    uint32_t mangle_policy = stored_policy(n, KS_NFT_CHAIN_MANGLE_OUTPUT);

    add_chain(n, KS_NFT_CHAIN_FILTER_INPUT, KS_NFT_TABLE_OPENSNITCH, KS_NFT_FAMILY_INET,
              PRIO_FILTER, TYPE_FILTER, NF_INET_LOCAL_IN, filter_policy);
    if (!commit(n)) {
        ks_error("Error while adding interception chains: Error adding DNS interception "
                 "chain filter_input-opensnitch-inet");
        return -1;
    }
    add_chain(n, KS_NFT_CHAIN_MANGLE_OUTPUT, KS_NFT_TABLE_OPENSNITCH, KS_NFT_FAMILY_INET,
              PRIO_MANGLE, TYPE_ROUTE, NF_INET_LOCAL_OUT, mangle_policy);
    if (!commit(n)) {
        ks_error("(1) Error adding interception chain mangle_output-opensnitch-inet, "
                 "trying with type Filter instead of Route");
        /* Workaround for kernels 4.x: GetChainPriority(inet, mangle, output) */
        add_chain(n, KS_NFT_CHAIN_MANGLE_OUTPUT, KS_NFT_TABLE_OPENSNITCH,
                  KS_NFT_FAMILY_INET, PRIO_MANGLE, TYPE_FILTER, NF_INET_LOCAL_OUT,
                  mangle_policy);
        if (!commit(n)) {
            ks_error("Error while adding interception chains: (2) Error adding "
                     "interception chain mangle_output-opensnitch-inet with type Filter. "
                     "Report it on github please, specifying the distro and the kernel");
            return -1;
        }
    }
    return 0;
}

/* DelChain */
static void del_chain(struct ks_nft *n, const struct chain *c)
{
    char key[sizeof(((struct chain_entry *)0)->key)];
    chain_key(c->name, c->table, c->family, key, sizeof(key));
    queue_del_chain(n, c);
    store_del_chain(n, key);
    if (!commit(n))
        ks_warning("[nftables] error deleting chain %s, %s", c->name, c->table);
}

/* GetChain (from the store) */
static struct chain *stored_chain(struct ks_nft *n, const char *name,
                                  const struct table_entry *t)
{
    if (t == NULL)
        return NULL;
    char key[sizeof(((struct chain_entry *)0)->key)];
    chain_key(name, t->name, t->fam, key, sizeof(key));
    struct chain_entry *e = store_get_chain(n, key);
    return e != NULL ? &e->c : NULL;
}

/* ---- rules.go ----------------------------------------------------- */

/* QueueDNSResponses */
static int queue_dns_responses(struct ks_nft *n)
{
    if (n->nl == NULL)
        return 0;
    struct table_entry *t = get_table(n, KS_NFT_TABLE_OPENSNITCH, KS_NFT_FAMILY_INET);
    struct chain *c = stored_chain(n, KS_NFT_CHAIN_FILTER_INPUT, t);
    if (t == NULL) {
        ks_error("QueueDNSResponses() Error getting table: opensnitch-%s", KS_NFT_FAMILY_INET);
    } else if (c == NULL) {
        ks_error("QueueDNSResponses() Error getting chain: filter_input-%s-%s", t->name,
                 KS_NFT_FAMILY_INET);
    } else {
        queue_new_rule(n, c, RULE_DNS, false); /* InsertRule, position 0 */
    }
    if (!commit(n)) {
        ks_error("Error while running DNS nftables rule: Error adding DNS interception rules");
        return -1;
    }
    return 0;
}

/* QueueConnections. Errors other than the commit are returned in the
 * second (unchecked) value upstream, so they are not logged. */
static int queue_connections(struct ks_nft *n)
{
    if (n->nl == NULL)
        return 0;
    struct table_entry *t = get_table(n, KS_NFT_TABLE_OPENSNITCH, KS_NFT_FAMILY_INET);
    if (t == NULL)
        return 0;
    struct chain *c = stored_chain(n, KS_NFT_CHAIN_MANGLE_OUTPUT, t);
    if (c == NULL)
        return 0;
    queue_new_rule(n, c, RULE_NOT_TCP_NEW, true);
    queue_new_rule(n, c, RULE_TCP_SYN, true);
    if (!commit(n)) {
        ks_error("Error while running conntrack nftables rule: Error adding interception rule ");
        return -1;
    }
    return 0;
}

/* delRulesByKey */
static int del_rules_by_key(struct ks_nft *n, const char *key)
{
    struct chain *chains;
    size_t nchains;
    if (list_chains(n, &chains, &nchains) < 0) {
        ks_warning("error listing nftables chains (%s): %s", key, strerror(errno));
        return -1;
    }
    for (size_t i = 0; i < nchains; i++) {
        const struct chain *c = &chains[i];
        struct rule *rules;
        size_t nrules;
        if (get_rules(n, c, &rules, &nrules) < 0) {
            ks_warning("Error listing rules (%s): %s", key, strerror(errno));
            continue;
        }
        size_t del = 0;
        for (size_t r = 0; r < nrules; r++) {
            if (!rule_has_key(&rules[r], key))
                continue;
            queue_del_rule(n, c, rules[r].handle);
            del++;
        }
        if (del > 0 && !commit(n))
            ks_warning("%s error deleting rules (%s)", LOG_TAG, key);
        if (nrules == 0 || nrules == del) {
            char ck[sizeof(((struct chain_entry *)0)->key)];
            chain_key(c->name, c->table, c->family, ck, sizeof(ck));
            if (store_get_chain(n, ck) != NULL)
                del_chain(n, c);
        }
        free_rules(rules, nrules);
    }
    free(chains);
    return 0;
}

/* DelInterceptionRules */
static void del_interception_rules(struct ks_nft *n)
{
    del_rules_by_key(n, KS_NFT_INTERCEPTION_KEY);
}

/* ---- system.go (the parts interception needs) --------------------- */

/* DeleteSystemRules. The system rules themselves arrive in phase 8; the
 * backup of chain policies (restoreBackupChains) has nothing to restore
 * until then. */
static void delete_system_rules(struct ks_nft *n, bool force, bool restore_chains)
{
    (void)restore_chains;
    if (del_rules_by_key(n, KS_NFT_SYSTEM_KEY) < 0)
        ks_warning("error deleting interception rules");
    if (force)
        del_system_tables(n);
}

/* ---- common.go: rules checker ------------------------------------- */

static void stop_checking_rules(struct ks_nft *n)
{
    if (n->checker != NULL) {
        ks_evloop_cancel_timer(n->loop, n->checker);
        n->checker = NULL;
        ks_info("exit checking firewall rules");
    }
}

static void reload_rules_step2(void *data)
{
    struct ks_nft *n = data;
    n->reload_timer = NULL;
    ks_nft_enable_interception(n);
}

/* ReloadRulesCallback */
static void reload_rules_callback(struct ks_nft *n)
{
    ks_important("nftables firewall rules changed, reloading");
    ks_nft_disable_interception(n, ks_log_get_level() == KS_LOG_DEBUG);
    /* upstream sleeps 500ms; we don't block the loop meanwhile */
    if (n->reload_timer == NULL)
        n->reload_timer = ks_evloop_add_timer(n->loop, RELOAD_DELAY_NS, 0,
                                              reload_rules_step2, n);
}

static void check_rules(void *data)
{
    struct ks_nft *n = data;
    if (!ks_nft_are_rules_loaded(n))
        reload_rules_callback(n);
}

/* NewRulesChecker */
static void new_rules_checker(struct ks_nft *n)
{
    char ival[KS_DURATION_STRLEN];
    ks_format_duration(n->check_interval, ival, sizeof(ival));
    if (strcmp(ival, "0s") == 0) {
        ks_info("Fw rules checker disabled ...");
        return;
    }
    stop_checking_rules(n);
    if (n->loop == NULL)
        return;
    ks_info("Starting new fw checker every %s ...", ival);
    n->checker = ks_evloop_add_timer(n->loop, n->check_interval, n->check_interval,
                                     check_rules, n);
}

/* SetRulesCheckerInterval */
static void set_rules_checker_interval(struct ks_nft *n, const char *interval)
{
    char err[256];
    int64_t ns;
    if (ks_parse_duration(interval, &ns, err, sizeof(err)) < 0) {
        char def[KS_DURATION_STRLEN];
        ks_format_duration(KS_FW_DEFAULT_CHECK_INTERVAL_NS, def, sizeof(def));
        ks_warning("Invalid rules checker interval (falling back to %s): %s", def, err);
        ns = KS_FW_DEFAULT_CHECK_INTERVAL_NS;
    } else if (ns < 0) {
        /* time.NewTicker panics on a negative interval */
        ks_warning("Invalid rules checker interval (%s), disabling the checker", interval);
        ns = 0;
    }
    n->check_interval = ns;
}

/* ---- public ------------------------------------------------------- */

struct ks_nft *ks_nft_new(struct ks_evloop *loop)
{
    struct ks_nft *n = calloc(1, sizeof(*n));
    if (n == NULL)
        return NULL;
    n->loop = loop;
    n->seq = 1;
    n->buf = malloc(BATCH_BUF_SIZE);
    n->rbuf = malloc(RECV_BUF_SIZE);
    n->batch = n->buf ? mnl_nlmsg_batch_start(n->buf, BATCH_BUF_SIZE) : NULL;
    if (n->batch == NULL || n->rbuf == NULL) {
        if (n->batch != NULL)
            mnl_nlmsg_batch_stop(n->batch);
        free(n->buf);
        free(n->rbuf);
        free(n);
        return NULL;
    }
    return n;
}

void ks_nft_free(struct ks_nft *n)
{
    if (n == NULL)
        return;
    stop_checking_rules(n);
    if (n->reload_timer != NULL)
        ks_evloop_cancel_timer(n->loop, n->reload_timer);
    conn_close(n);
    mnl_nlmsg_batch_stop(n->batch);
    free(n->buf);
    free(n->rbuf);
    free(n->tables);
    free(n->chains);
    free(n->config_path);
    free(n);
}

void ks_nft_init(struct ks_nft *n, uint16_t queue_num, const char *config_path,
                 const char *monitor_interval, bool bypass_queue)
{
    if (n->running)
        return;
    n->bypass_queue = bypass_queue;
    conn_open(n);
    init_maps_store(n);
    n->queue_num = queue_num;
    set_rules_checker_interval(n, monitor_interval);
    free(n->config_path);
    n->config_path = strdup(config_path);

    /* Start from a clean state: the daemon may have exited unexpectedly,
     * leaving rules behind. */
    del_interception_rules(n);
    ks_nft_enable_interception(n);
    n->running = true;
}

void ks_nft_stop(struct ks_nft *n)
{
    if (!n->running)
        return;
    stop_checking_rules(n);
    ks_nft_clean_rules(n, ks_log_get_level() == KS_LOG_DEBUG);
    n->running = false;
}

bool ks_nft_is_running(const struct ks_nft *n)
{
    return n != NULL && n->running;
}

void ks_nft_enable_interception(struct ks_nft *n)
{
    char err[512];
    if (add_interception_tables(n, err, sizeof(err)) < 0) {
        ks_error("Error while adding interception tables: %s", err);
        return;
    }
    if (add_interception_chains(n) < 0)
        return;
    queue_dns_responses(n);
    queue_connections(n);
    new_rules_checker(n);
}

void ks_nft_disable_interception(struct ks_nft *n, bool log_errors)
{
    (void)log_errors;
    stop_checking_rules(n);
    if (n->reload_timer != NULL) {
        ks_evloop_cancel_timer(n->loop, n->reload_timer);
        n->reload_timer = NULL;
    }
    del_interception_rules(n);
}

void ks_nft_clean_rules(struct ks_nft *n, bool log_errors)
{
    ks_nft_disable_interception(n, log_errors);
    delete_system_rules(n, true, true);
}

bool ks_nft_are_rules_loaded(struct ks_nft *n)
{
    struct chain *chains;
    size_t nchains;
    if (list_chains(n, &chains, &nchains) < 0) {
        ks_warning("[nftables] error listing nftables chains: %s", strerror(errno));
        return false;
    }
    int nrules_found = 0;
    bool ok = true;
    for (size_t i = 0; i < nchains && ok; i++) {
        const struct chain *c = &chains[i];
        if (strcmp(c->table, KS_NFT_TABLE_OPENSNITCH) != 0)
            continue;
        struct rule *rules;
        size_t nrules;
        if (get_rules(n, c, &rules, &nrules) < 0) {
            ks_warning("[nftables] Error listing rules: %s", strerror(errno));
            continue;
        }
        for (size_t r = 0; r < nrules && ok; r++) {
            if (!rule_has_key(&rules[r], KS_NFT_INTERCEPTION_KEY))
                continue;
            if (strcmp(c->name, KS_NFT_CHAIN_FILTER_INPUT) == 0 && r != 0) {
                ks_warning("nftables DNS rule not in 1st position (%zu)", r);
                ok = false;
                break;
            }
            nrules_found++;
            if (strcmp(c->name, KS_NFT_CHAIN_MANGLE_OUTPUT) == 0 && r + 2 < nrules) {
                ks_warning("nftables queue rule is not the latest of the list (%zu/%zu), "
                           "reloading", r, nrules);
                ok = false;
            }
        }
        free_rules(rules, nrules);
    }
    free(chains);
    if (!ok)
        return false;
    /* exactly 3 rules: 2 queue and 1 dns */
    if (nrules_found != 3) {
        ks_warning("nfables filter rules not loaded: %d", nrules_found);
        return false;
    }
    return true;
}

int64_t ks_nft_check_interval(const struct ks_nft *n)
{
    return n->check_interval;
}

int ks_nft_count_rules(struct ks_nft *n, const char *key)
{
    if (!conn_open(n))
        return -1;
    struct chain *chains;
    size_t nchains;
    if (list_chains(n, &chains, &nchains) < 0)
        return -1;
    int count = 0;
    for (size_t i = 0; i < nchains; i++) {
        struct rule *rules;
        size_t nrules;
        if (get_rules(n, &chains[i], &rules, &nrules) < 0)
            continue;
        for (size_t r = 0; r < nrules; r++)
            count += rule_has_key(&rules[r], key);
        free_rules(rules, nrules);
    }
    free(chains);
    return count;
}

static int table_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nftnl_table *t = nftnl_table_alloc();
    if (t == NULL)
        return MNL_CB_OK;
    const char **names = data;
    if (nftnl_table_nlmsg_parse(nlh, t) == 0 && nftnl_table_is_set(t, NFTNL_TABLE_NAME) &&
        strcmp(nftnl_table_get_str(t, NFTNL_TABLE_NAME), names[0]) == 0)
        names[1] = "found";
    nftnl_table_free(t);
    return MNL_CB_OK;
}

int ks_nft_table_exists(struct ks_nft *n, const char *name)
{
    if (!conn_open(n))
        return -1;
    char buf[REQ_BUF_SIZE];
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, NFPROTO_UNSPEC,
                                                 NLM_F_DUMP | NLM_F_ACK, n->seq++);
    const char *data[2] = {name, NULL};
    if (dump(n, nlh, table_cb, data) < 0)
        return -1;
    return data[1] != NULL;
}
