/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall on nftables: port of upstream
 * daemon/firewall/nftables/system.go, the system parts of chains.go
 * (addRegularChain, backupExistingChains, restoreBackupChains), utils.go
 * (GetHook, GetChainPriority, GetConntrackPriority), rules.go (InsertRule)
 * and the configuration callbacks of monitor.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/fw/nft_priv.h"

#include <libnftnl/chain.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"

/* google/nftables ChainPriority* */
#define PRIO_RAW (-300)
#define PRIO_SELINUX_FIRST (-225)
#define PRIO_CONNTRACK (-200)
#define PRIO_NAT_DEST (-100)
#define PRIO_SECURITY 50
#define PRIO_NAT_SOURCE 100
#define PRIO_SELINUX_LAST 225
#define PRIO_CONNTRACK_HELPER 300
#define PRIO_CONNTRACK_CONFIRM 2147483647
#define TYPE_NAT "nat"

static bool ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a >= 'A' && *a <= 'Z' ? (char)(*a - 'A' + 'a') : *a;
        if (x != *b)
            return false;
    }
    return *a == *b;
}

/* GetHook: output unless one of the others. */
static uint32_t get_hook(const char *hook)
{
    if (ieq(hook, "input"))
        return NF_INET_LOCAL_IN;
    if (ieq(hook, "prerouting"))
        return NF_INET_PRE_ROUTING;
    if (ieq(hook, "postrouting"))
        return NF_INET_POST_ROUTING;
    if (ieq(hook, "forward"))
        return NF_INET_FORWARD;
    if (ieq(hook, "ingress"))
        return NF_NETDEV_INGRESS;
    return NF_INET_LOCAL_OUT;
}

static void to_lower(const char *s, char *buf, size_t len)
{
    size_t i;
    for (i = 0; i + 1 < len && s[i]; i++)
        buf[i] = s[i] >= 'A' && s[i] <= 'Z' ? (char)(s[i] - 'A' + 'a') : s[i];
    buf[i] = '\0';
}

/* GetConntrackPriority */
static void conntrack_priority(const char *hook, int32_t *prio, const char **type)
{
    *type = TYPE_FILTER;
    *prio = PRIO_CONNTRACK;
    if (strcmp(hook, "output") == 0) {
        *prio = PRIO_NAT_SOURCE;
    } else if (strcmp(hook, "postrouting") == 0) {
        *prio = PRIO_CONNTRACK_HELPER;
        *type = TYPE_NAT;
    } else if (strcmp(hook, "input") == 0) {
        *prio = PRIO_CONNTRACK_CONFIRM;
    }
}

/* GetChainPriority: false for invalid combinations (upstream's nil). */
static bool chain_priority(const char *family_, const char *ctype_, const char *hook_,
                           int32_t *prio, const char **type)
{
    char family[32], ctype[32], hook[32];
    to_lower(family_, family, sizeof(family));
    to_lower(ctype_, ctype, sizeof(ctype));
    to_lower(hook_, hook, sizeof(hook));
    *type = TYPE_FILTER;
    *prio = PRIO_FILTER;

    bool nat = strcmp(ctype, "natdest") == 0 || strcmp(ctype, "natsource") == 0;
    if (nat && strcmp(hook, "forward") == 0) {
        ks_warning("[nftables] invalid nat combination of tables and hooks. chain: %s, hook: %s",
                   ctype, hook);
        return false;
    }
    bool filter = strcmp(ctype, "filter") == 0;
    if (strcmp(family, "netdev") == 0 && (!filter || strcmp(hook, "ingress") != 0)) {
        ks_warning("[nftables] invalid netdev combination of tables and hooks. chain: %s, "
                   "hook: %s", ctype, hook);
        return false;
    }
    if (strcmp(family, "arp") == 0 &&
        (!filter || (strcmp(hook, "output") != 0 && strcmp(hook, "input") != 0))) {
        ks_warning("[nftables] invalid arp combination of tables and hooks. chain: %s, hook: %s",
                   ctype, hook);
        return false;
    }
    if (strcmp(family, "bridge") == 0 &&
        (!filter || strcmp(hook, "egress") == 0 || strcmp(hook, "ingress") == 0)) {
        ks_warning("[nftables] invalid bridge combination of tables and hooks. chain: %s, "
                   "hook: %s", ctype, hook);
        return false;
    }

    if (filter) {
        if (strcmp(family, "bridge") == 0) {
            *prio = PRIO_CONNTRACK;
            if (strcmp(hook, "prerouting") == 0)
                *prio = PRIO_RAW;
            else if (strcmp(hook, "output") == 0)
                *prio = PRIO_NAT_SOURCE;
            else if (strcmp(hook, "postrouting") == 0)
                *prio = PRIO_CONNTRACK_HELPER;
        }
    } else if (strcmp(ctype, "mangle") == 0) {
        /* mangle chains must be of type filter on some kernels (4.19) */
        *prio = PRIO_MANGLE;
    } else if (strcmp(ctype, "raw") == 0) {
        *prio = PRIO_RAW;
    } else if (strcmp(ctype, "conntrack") == 0) {
        conntrack_priority(hook, prio, type);
    } else if (strcmp(ctype, "natdest") == 0) {
        *prio = strcmp(hook, "output") == 0 ? PRIO_NAT_SOURCE : PRIO_NAT_DEST;
        *type = TYPE_NAT;
    } else if (strcmp(ctype, "natsource") == 0) {
        *prio = PRIO_NAT_SOURCE;
        *type = TYPE_NAT;
    } else if (strcmp(ctype, "security") == 0) {
        *prio = PRIO_SECURITY;
    } else if (strcmp(ctype, "selinux") == 0) {
        *prio = strcmp(hook, "postrouting") != 0 ? PRIO_SELINUX_LAST : PRIO_SELINUX_FIRST;
    }
    return true;
}

/* addRegularChain: a chain without hook, type or policy. */
static void add_regular_chain(struct ks_nft *n, const char *name, const char *table,
                              const char *family)
{
    struct table_entry *t = ks_nftp_get_table(n, table, family);
    if (t == NULL) {
        ks_debug("%s addRegularChain, Error getting table: %s, %s", LOG_TAG, table, family);
        return;
    }
    struct chain c;
    memset(&c, 0, sizeof(c));
    snprintf(c.name, sizeof(c.name), "%s", name);
    snprintf(c.table, sizeof(c.table), "%s", t->name);
    c.family = t->fam;
    ks_nftp_queue_new_chain(n, &c);
    char key[sizeof(((struct chain_entry *)0)->key)];
    ks_nftp_chain_key(name, t->name, t->fam, key, sizeof(key));
    ks_nftp_store_put_chain(n, key, &c);
}

/* CreateSystemRule: the table and the chain of a configured chain. */
static bool create_system_rule(struct ks_nft *n, const struct ks_fw_chain *ch)
{
    if (ks_fw_chain_is_invalid(ch)) {
        ks_warning("%s CreateSystemRule(), Chain's field Name and Family cannot be empty",
                   LOG_TAG);
        return false;
    }
    char err[512];
    ks_nftp_add_table(n, ch->table, ch->family, err, sizeof(err));

    if (ch->hook[0] == '\0' && ch->type[0] == '\0') {
        add_regular_chain(n, ch->name, ch->table, ch->family);
        return ks_nftp_commit(n);
    }
    uint32_t policy = ieq(ch->policy, "drop") ? NF_DROP : NF_ACCEPT;
    uint32_t hook = get_hook(ch->hook);
    int32_t prio;
    const char *type;
    if (!chain_priority(ch->family, ch->type, ch->hook, &prio, &type)) {
        ks_warning("%s Invalid system firewall combination: %s, %s", LOG_TAG, ch->type,
                   ch->hook);
        return false;
    }
    if (!ks_nftp_add_chain(n, ch->name, ch->table, ch->family, prio, type, hook, policy)) {
        ks_warning("%s error adding chain: %s, table: %s", LOG_TAG, ch->name, ch->table);
        return false;
    }
    return ks_nftp_commit(n);
}

/* InsertRule: queues `r` in the chain at `position` (0: the top) with the
 * system key, and commits. */
static int insert_rule(struct ks_nft *n, const struct ks_fw_chain *ch, uint64_t position,
                       struct nftnl_rule *r, char *err, size_t errlen)
{
    struct table_entry *t = ks_nftp_get_table(n, ch->table, ch->family);
    struct chain *c = t != NULL ? ks_nftp_stored_chain(n, ch->name, t) : NULL;
    if (t == NULL || c == NULL) {
        snprintf(err, errlen, "%s getting table: %s, %s", LOG_TAG, ch->table, ch->family);
        return -1;
    }
    char *room = ks_nftp_batch_room(n);
    if (room == NULL) {
        snprintf(err, errlen, "rule not added");
        return -1;
    }
    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, t->name);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, c->name);
    nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, t->fam);
    nftnl_rule_set_data(r, NFTNL_RULE_USERDATA, KS_NFT_SYSTEM_KEY,
                        (uint32_t)strlen(KS_NFT_SYSTEM_KEY));
    if (position != 0)
        nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, position);
    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(room, NFT_MSG_NEWRULE, t->fam,
                                                 NLM_F_CREATE | NLM_F_ACK, n->seq++);
    nftnl_rule_nlmsg_build_payload(nlh, r);
    ks_nftp_batch_added(n);
    if (!ks_nftp_commit(n)) {
        snprintf(err, errlen, "rule not added");
        return -1;
    }
    return 0;
}

/* AddSystemRule */
static int add_system_rule(struct ks_nft *n, const struct ks_fw_rule *rule,
                           const struct ks_fw_chain *ch, char *err, size_t errlen)
{
    struct nftnl_rule *r = nftnl_rule_alloc();
    if (r == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    int ret = 0;
    for (size_t i = 0; i < rule->expressions.len; i++) {
        const struct ks_fw_expression *e = KS_SYSFW_EXPR(rule, i);
        if (!ks_nftp_parse_expression(n, r, ch->table, ch->name, ch->family, e)) {
            snprintf(err, errlen, "%s invalid rule parameters: &{%s}", rule->uuid,
                     e->statement != NULL ? e->statement->name : "<nil>");
            ret = -1;
            goto out;
        }
    }
    struct nftnl_expr_iter *it = nftnl_expr_iter_create(r);
    bool has_exprs = it != NULL && nftnl_expr_iter_next(it) != NULL;
    nftnl_expr_iter_destroy(it);
    if (has_exprs) {
        if (!ks_nftp_add_verdict(r, rule->target, rule->target_parameters)) {
            snprintf(err, errlen, "%s invalid verdict %s %s", rule->uuid, rule->target,
                     rule->target_parameters);
            ret = -1;
            goto out;
        }
        ret = insert_rule(n, ch, rule->position, r, err, errlen);
    }
out:
    nftnl_rule_free(r);
    return ret;
}

/* backupExistingChains: chains with policy accept, to set them back to
 * accept if the configuration changes them to drop. */
static void backup_existing_chains(struct ks_nft *n)
{
    struct chain *chains;
    size_t nchains;
    if (ks_nftp_list_chains(n, &chains, &nchains) < 0)
        return;
    for (size_t i = 0; i < nchains; i++) {
        const struct chain *c = &chains[i];
        if (!c->has_policy || c->policy != NF_ACCEPT)
            continue;
        ks_debug("%s backing up existing chain with policy ACCEPT: %s, %s", LOG_TAG, c->name,
                 c->table);
        /* origSysChains[key] = c */
        size_t j;
        for (j = 0; j < n->norig_chains; j++) {
            const struct chain *o = &n->orig_chains[j];
            if (strcmp(o->name, c->name) == 0 && strcmp(o->table, c->table) == 0 &&
                o->family == c->family)
                break;
        }
        if (j == n->norig_chains) {
            struct chain *v = realloc(n->orig_chains, (j + 1) * sizeof(*v));
            if (v == NULL)
                break;
            n->orig_chains = v;
            n->norig_chains++;
        }
        n->orig_chains[j] = *c;
    }
    free(chains);
}

/* restoreBackupChains */
static void restore_backup_chains(struct ks_nft *n)
{
    for (size_t i = 0; i < n->norig_chains; i++) {
        struct chain *c = &n->orig_chains[i];
        ks_debug("%s Restoring chain policy to accept: %s, %s", LOG_TAG, c->name, c->table);
        c->policy = NF_ACCEPT;
        ks_nftp_queue_new_chain(n, c);
    }
    ks_nftp_commit(n);
}

void ks_nftp_add_system_rules(struct ks_nft *n, bool reload, bool backup_chains)
{
    (void)reload;
    struct ks_sysfw *cfg = &n->conf.cfg;
    if (!cfg->enabled) {
        ks_important("[nftables] AddSystemRules() fw disabled");
        return;
    }
    if (backup_chains)
        backup_existing_chains(n);

    for (size_t i = 0; i < cfg->system_rules.len; i++) {
        struct ks_fw_chains_list *l = KS_SYSFW_RULES(cfg, i);
        for (size_t j = 0; j < l->chains.len; j++) {
            struct ks_fw_chain *ch = KS_SYSFW_CHAIN(l, j);
            if (!create_system_rule(n, ch)) {
                ks_info("createSystem failed: %s %s", ch->name, ch->table);
                continue;
            }
            /* inserted at the top in reverse order: they end up in order */
            for (size_t k = ch->rules.len; k-- > 0;) {
                struct ks_fw_rule *rule = KS_SYSFW_RULE(ch, k);
                if (rule->uuid == NULL || rule->uuid[0] == '\0') {
                    char uuid[KS_UUID_STRLEN];
                    char *dup;
                    if (ks_fw_new_uuid(uuid, sizeof(uuid)) == 0 && (dup = strdup(uuid))) {
                        free(rule->uuid);
                        rule->uuid = dup;
                    }
                }
                if (!rule->enabled)
                    continue;
                char err[1024];
                if (add_system_rule(n, rule, ch, err, sizeof(err)) < 0) {
                    char msg[1200];
                    snprintf(msg, sizeof(msg), "%s (%s)", err, rule->uuid);
                    ks_fw_errors_send(&n->errors, msg);
                }
            }
        }
    }
}

void ks_nftp_delete_system_rules(struct ks_nft *n, bool force, bool restore_chains)
{
    if (ks_nftp_del_rules_by_key(n, KS_NFT_SYSTEM_KEY) < 0)
        ks_warning("error deleting interception rules");
    if (restore_chains)
        restore_backup_chains(n);
    if (force)
        ks_nftp_del_system_tables(n);
}

/* PreloadConfCallback: before the configuration is (re)loaded. */
static void preload_conf_callback(void *data)
{
    struct ks_nft *n = data;
    ks_info("nftables config changed, reloading");
    ks_nftp_delete_system_rules(n, false, true);
}

/* ReloadConfCallback: after the configuration file changes. */
static void reload_conf_callback(void *data)
{
    struct ks_nft *n = data;
    ks_important("reloadConfCallback changed, reloading");
    ks_nftp_delete_system_rules(n, false, false);
    ks_nftp_add_system_rules(n, true, false);
}

/* NewSystemFwConfig + LoadDiskConfiguration(!reload) */
void ks_nftp_sys_init(struct ks_nft *n, const char *config_path)
{
    if (n->conf_ready)
        ks_sysfw_conf_destroy(&n->conf);
    n->conf_ready = ks_sysfw_conf_init(&n->conf, n->loop, config_path, preload_conf_callback,
                                       reload_conf_callback, n) == 0;
    if (n->conf_ready)
        ks_sysfw_conf_load(&n->conf, false);
}

/* StopConfigWatcher. The configuration stays for Serialize(). */
void ks_nftp_sys_stop(struct ks_nft *n)
{
    if (!n->conf_ready)
        return;
    struct ks_sysfw keep = n->conf.cfg;
    char *file = n->conf.file;
    n->conf.file = NULL;
    memset(&n->conf.cfg, 0, sizeof(n->conf.cfg));
    ks_sysfw_conf_destroy(&n->conf);
    /* a configuration without a watcher */
    ks_sysfw_conf_init(&n->conf, NULL, file, preload_conf_callback, reload_conf_callback, n);
    free(file);
    ks_sysfw_free(&n->conf.cfg);
    n->conf.cfg = keep;
}
