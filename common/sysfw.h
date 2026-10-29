/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall configuration (system-fw.json) shared by the daemon
 * and the UI: port of upstream daemon/firewall/config/config.go (the
 * types), the Serialize()/Deserialize() of daemon/firewall/{nftables,
 * iptables} (protobuf <-> JSON), and the protobuf -> Go struct copy the UI
 * needs to edit what a daemon sent.
 *
 * The JSON is decoded with encoding/json's rules (common/json_schema.h);
 * the protobuf form (SysFirewall) is what goes between daemon and UI; and
 * the text saved from the UI's changes is what golang/protobuf's jsonpb
 * writes, so the file is byte for byte the one upstream writes.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_sysfw owns everything reachable from it (strings,
 * arrays, pointed-to rules and statements); release with ks_sysfw_free().
 */
#ifndef KS_COMMON_SYSFW_H
#define KS_COMMON_SYSFW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/arena.h"
#include "common/json_schema.h"
#include "common/pb/ui.pb-c.h"

/* Upper bound for system-fw.json. */
#define KS_SYSFW_MAX_SIZE (16 * 1024 * 1024)

/* config.ExprValues */
struct ks_fw_expr_value {
    char *key;   /* Key */
    char *value; /* Value */
};

/* config.ExprStatement */
struct ks_fw_statement {
    char *op;            /* Op: ==, !=, ... */
    char *name;          /* Name: tcp, udp, ct, ip, log, ... */
    struct ks_array values; /* Values: struct ks_fw_expr_value */
};

/* config.Expressions */
struct ks_fw_expression {
    struct ks_fw_statement *statement; /* Statement; NULL is Go's nil */
};

/* config.FwRule */
struct ks_fw_rule {
    char *chain;      /* Chain (deprecated, iptables) */
    char *table;      /* Table (deprecated, iptables) */
    char *parameters; /* Parameters (deprecated, iptables) */
    char *uuid;
    char *description;
    char *target;
    char *target_parameters;
    struct ks_array expressions; /* struct ks_fw_expression */
    uint64_t position;           /* `json:",string"` */
    bool enabled;
};

/* config.FwChain */
struct ks_fw_chain {
    char *table;
    char *family;
    char *name;
    char *description;
    char *priority;
    char *type;
    char *hook;
    char *policy;
    struct ks_array rules; /* struct ks_fw_rule */
};

/* config.chainsList */
struct ks_fw_chains_list {
    struct ks_fw_rule *rule; /* Rule (deprecated, iptables); NULL is nil */
    struct ks_array chains;  /* struct ks_fw_chain */
};

/* config.SystemConfig */
struct ks_sysfw {
    struct ks_array system_rules; /* struct ks_fw_chains_list */
    uint32_t version;
    bool enabled;
};

#define KS_SYSFW_RULES(cfg, i) KS_ARRAY_ITEM((cfg)->system_rules, struct ks_fw_chains_list, i)
#define KS_SYSFW_CHAIN(list, i) KS_ARRAY_ITEM((list)->chains, struct ks_fw_chain, i)
#define KS_SYSFW_RULE(chain, i) KS_ARRAY_ITEM((chain)->rules, struct ks_fw_rule, i)
#define KS_SYSFW_EXPR(rule, i) KS_ARRAY_ITEM((rule)->expressions, struct ks_fw_expression, i)
#define KS_SYSFW_VALUE(st, i) KS_ARRAY_ITEM((st)->values, struct ks_fw_expr_value, i)

extern const struct ks_schema ks_sysfw_schema;
extern const struct ks_schema ks_fw_rule_schema;
extern const struct ks_schema ks_fw_chain_schema;

/* json.Unmarshal into a zeroed SystemConfig. On error returns -1, leaves
 * `out` empty and fills `err`. */
int ks_sysfw_parse(const char *buf, size_t len, struct ks_sysfw *out, char *err,
                   size_t errlen);
void ks_sysfw_free(struct ks_sysfw *cfg);
/* Deep copy into `dst`. -1 on OOM. */
int ks_sysfw_copy(struct ks_sysfw *dst, const struct ks_sysfw *src);

/* FwChain.IsInvalid */
bool ks_fw_chain_is_invalid(const struct ks_fw_chain *c);

/* Serialize(): the configuration as a protobuf message allocated in `a`.
 * NULL on OOM. Strings are made valid UTF-8 as json.Marshal does. */
Protocol__SysFirewall *ks_sysfw_to_pb(struct ks_arena *a, const struct ks_sysfw *cfg);

/* Deserialize(): jsonpb.Marshaler{OrigName: true, EmitDefaults:
 * `emit_defaults`, Indent: "  "} of `fw` (nftables emits defaults,
 * iptables doesn't). Returns a malloc'd string, or NULL on OOM. */
char *ks_sysfw_pb_to_json(const Protocol__SysFirewall *fw, bool emit_defaults);

/* The protobuf message as a struct (for the UI to edit). -1 on OOM. */
int ks_sysfw_from_pb(struct ks_sysfw *out, const Protocol__SysFirewall *fw);

/* uuid.New().String() (Go): a random (version 4) UUID. `buf` has room for
 * KS_UUID_STRLEN bytes. Returns 0, or -1 if no randomness is available. */
#define KS_UUID_STRLEN 37
int ks_fw_new_uuid(char *buf, size_t len);
/* str(uuid.uuid1()) (Python): time-based, with this host's MAC address (or
 * a random multicast one) as node. */
int ks_fw_new_uuid1(char *buf, size_t len);

#endif
