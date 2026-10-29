/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internals shared by the nftables firewall's files (nft.c: the netlink
 * connection, stores and interception; nft_sys.c: the system firewall;
 * nft_exprs.c: the expressions of system rules). Not a public API.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: see daemon/fw/nft.h. The arrays returned by ks_nftp_list_chains()
 * and ks_nftp_get_rules() belong to the caller.
 */
#ifndef KS_DAEMON_FW_NFT_PRIV_H
#define KS_DAEMON_FW_NFT_PRIV_H

/* glibc's netinet/in.h must come before the kernel headers */
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <linux/netfilter/nf_tables.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/duration.h"
#include "daemon/fw/nft.h"
#include "daemon/fw/sysfw.h"

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

    /* system firewall (system.go) */
    struct ks_sysfw_conf conf; /* config.Config */
    bool conf_ready;
    struct ks_fw_errors errors;   /* ErrChan */
    struct chain *orig_chains;    /* origSysChains */
    size_t norig_chains;
    uint32_t set_id;              /* google/nftables' allocSetID */

    int64_t check_interval;
    bool running;
    struct ks_timer *checker;
    struct ks_timer *reload_timer;
};


/* netlink (nft.c) */
char *ks_nftp_batch_room(struct ks_nft *n);
void ks_nftp_batch_added(struct ks_nft *n);
bool ks_nftp_commit(struct ks_nft *n);
int ks_nftp_list_chains(struct ks_nft *n, struct chain **out, size_t *count);
int ks_nftp_get_rules(struct ks_nft *n, const struct chain *c, struct rule **out,
                      size_t *count);
void ks_nftp_free_rules(struct rule *v, size_t count);
bool ks_nftp_rule_has_key(const struct rule *r, const char *key);
void ks_nftp_queue_new_chain(struct ks_nft *n, const struct chain *c);
void ks_nftp_queue_del_chain(struct ks_nft *n, const struct chain *c);

/* expressions shared with the interception rules (nft.c) */
bool ks_nftp_add_expr(struct nftnl_rule *r, struct nftnl_expr *e);
bool ks_nftp_e_meta_l4proto(struct nftnl_rule *r);
bool ks_nftp_e_cmp(struct nftnl_rule *r, enum nft_cmp_ops op, const void *data, uint32_t len);
bool ks_nftp_e_payload_th(struct nftnl_rule *r, uint32_t offset, uint32_t len);
bool ks_nftp_e_bitwise(struct nftnl_rule *r, const void *mask, const void *xor, uint32_t len);

/* stores (nft.c) */
uint8_t ks_nftp_family_code(const char *family);
void ks_nftp_chain_key(const char *name, const char *table, uint8_t fam, char *buf,
                       size_t len);
struct table_entry *ks_nftp_get_table(struct ks_nft *n, const char *name, const char *family);
struct chain_entry *ks_nftp_store_get_chain(struct ks_nft *n, const char *key);
void ks_nftp_store_del_chain(struct ks_nft *n, const char *key);
void ks_nftp_store_put_chain(struct ks_nft *n, const char *key, const struct chain *c);
struct chain *ks_nftp_stored_chain(struct ks_nft *n, const char *name,
                                   const struct table_entry *t);

/* tables.go, chains.go, rules.go (nft.c) */
struct table_entry *ks_nftp_add_table(struct ks_nft *n, const char *name, const char *family,
                                      char *err, size_t errlen);
void ks_nftp_del_system_tables(struct ks_nft *n);
bool ks_nftp_kernel_get_chain(struct ks_nft *n, const char *name, const struct table_entry *t,
                              const char *family, struct chain *out);
bool ks_nftp_add_chain(struct ks_nft *n, const char *name, const char *table,
                       const char *family, int32_t prio, const char *type,
                       uint32_t hooknum, uint32_t policy);
void ks_nftp_del_chain(struct ks_nft *n, const struct chain *c);
int ks_nftp_del_rules_by_key(struct ks_nft *n, const char *key);

/* system.go (nft_sys.c) */
void ks_nftp_sys_init(struct ks_nft *n, const char *config_path);
void ks_nftp_sys_stop(struct ks_nft *n);
void ks_nftp_add_system_rules(struct ks_nft *n, bool reload, bool backup_chains);
void ks_nftp_delete_system_rules(struct ks_nft *n, bool force, bool restore_chains);

/* parser.go, rule_helpers.go, exprs/ (nft_exprs.c): appends the expressions
 * of `e` to `r`, queueing the sets they need. false (logged) if invalid. */
bool ks_nftp_parse_expression(struct ks_nft *n, struct nftnl_rule *r, const char *table,
                              const char *chain, const char *family,
                              const struct ks_fw_expression *e);
/* NewExprVerdict: false if the target is invalid. */
bool ks_nftp_add_verdict(struct nftnl_rule *r, const char *target, const char *parms);

#endif
