/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Rules and operators. Port of upstream daemon/rule/rule.go, operator.go,
 * operator_lists.go and operator_aliases.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: a struct ks_rule owns its strings, its operator tree and the
 * compiled state of every operator (regexps, loaded lists, list monitors).
 * Free with ks_rule_free().
 */
#ifndef KS_DAEMON_RULES_RULE_H
#define KS_DAEMON_RULES_RULE_H

#include <stdbool.h>
#include <stddef.h>

#include "common/json_schema.h"
#include "daemon/conn.h"

struct ks_evloop;
struct ks_aliases;

/* Actions, durations, types and operands: verbatim from upstream. */
#define KS_ACTION_ALLOW  "allow"
#define KS_ACTION_DENY   "deny"
#define KS_ACTION_REJECT "reject"

#define KS_TYPE_SIMPLE  "simple"
#define KS_TYPE_REGEXP  "regexp"
#define KS_TYPE_COMPLEX "complex" /* reserved upstream, rejected by Compile */
#define KS_TYPE_LIST    "list"
#define KS_TYPE_NETWORK "network"
#define KS_TYPE_LISTS   "lists"

#define KS_OP_TRUE                 "true"
#define KS_OP_PROCESS_ID           "process.id"
#define KS_OP_PROCESS_PATH         "process.path"
#define KS_OP_PROCESS_PARENT_PATH  "process.parent.path"
#define KS_OP_PROCESS_CMD          "process.command"
#define KS_OP_PROCESS_ENV_PREFIX   "process.env."
#define KS_OP_PROCESS_HASH_MD5     "process.hash.md5"
#define KS_OP_PROCESS_HASH_SHA1    "process.hash.sha1"
#define KS_OP_USER_ID              "user.id"
#define KS_OP_USER_NAME            "user.name"
#define KS_OP_SRC_IP               "source.ip"
#define KS_OP_SRC_PORT             "source.port"
#define KS_OP_DST_IP               "dest.ip"
#define KS_OP_DST_HOST             "dest.host"
#define KS_OP_DST_PORT             "dest.port"
#define KS_OP_DST_NETWORK          "dest.network"
#define KS_OP_SRC_NETWORK          "source.network"
#define KS_OP_PROTO                "protocol"
#define KS_OP_IFACE_IN             "iface.in"
#define KS_OP_IFACE_OUT            "iface.out"
#define KS_OP_LIST                 "list"
#define KS_OP_DOMAINS_LISTS        "lists.domains"
#define KS_OP_DOMAINS_REGEXP_LISTS "lists.domains_regexp"
#define KS_OP_IP_LISTS             "lists.ips"
#define KS_OP_NET_LISTS            "lists.nets"
#define KS_OP_HASH_MD5_LISTS       "lists.hash.md5"

struct ks_op_state;

/* rule.Operator. JSON fields first, in Go's order. */
struct ks_operator {
    char *operand;           /* operand */
    char *data;              /* data */
    char *type;              /* type */
    struct ks_array list;    /* list: struct ks_operator */
    bool sensitive;          /* sensitive */
    struct ks_op_state *st;  /* compiled state; NULL until compiled */
};

/* rule.Rule. */
struct ks_rule {
    char *created;               /* created (RFC 3339) */
    char *updated;               /* updated */
    char *name;                  /* name */
    char *description;           /* description */
    char *action;                /* action */
    char *duration;              /* duration */
    struct ks_operator operator; /* operator */
    bool enabled;                /* enabled */
    bool precedence;             /* precedence */
    bool nolog;                  /* nolog */
};

/* What compiling needs from the outside: the loop that runs list monitors
 * (NULL: lists are read once and never refreshed) and the network aliases
 * (NULL: none). */
struct ks_rules_env {
    struct ks_evloop *loop;
    const struct ks_aliases *aliases;
};

/* Parses a rule from JSON (json.Unmarshal into rule.Rule). The rule is not
 * compiled. Returns NULL with `err` filled on error. */
struct ks_rule *ks_rule_parse(const char *json, size_t len, char *err,
                              size_t errlen);

/* json.MarshalIndent(rule, "", "  "). malloc'd; NULL on OOM. */
char *ks_rule_to_json(const struct ks_rule *r);

/* rule.Create: a new rule with Created set to now (RFC 3339). `op` is
 * deep-copied (uncompiled). NULL on OOM. */
struct ks_rule *ks_rule_create(const char *name, const char *description,
                               bool enabled, bool precedence, bool nolog,
                               const char *action, const char *duration,
                               const struct ks_operator *op);

/* Deep copy of the JSON fields (the copy is not compiled). */
struct ks_rule *ks_rule_copy(const struct ks_rule *r);

void ks_rule_free(struct ks_rule *r);

/* time.Now().Format(time.RFC3339), as upstream stamps rules. */
void ks_rfc3339_now(char *buf, size_t len);

/* Rule.String() without colors:
 * "[Enabled] name: if(operand is 'data'){ action duration }". */
void ks_rule_describe(const struct ks_rule *r, char *buf, size_t len);

/* Operator.Compile(). Idempotent once it succeeded (like upstream, except
 * for user.name operators, which upstream recompiles every time). */
int ks_operator_compile(struct ks_operator *o, const struct ks_rules_env *env,
                        char *err, size_t errlen);

/* Operator.Match(). `c` may be NULL only for the "true" operand. */
bool ks_operator_match(const struct ks_operator *o, const struct ks_conn *c,
                       bool has_checksums);

/* Drops compiled state (regexps, lists, list monitors) of `o` and of every
 * operator in its list; Operator.StopMonitoringLists() and ClearLists(). */
void ks_operator_reset(struct ks_operator *o);

/* Frees the compiled state and every field of `o` (not `o` itself) and
 * zeroes it. */
void ks_operator_clear(struct ks_operator *o);

/* Parses operators from a JSON array (the deprecated "data" form of list
 * rules: json.Unmarshal into []Operator). */
int ks_operator_list_parse(const char *json, struct ks_array *out, char *err,
                           size_t errlen);

/* Number of entries loaded by a "lists" operator (0 for other types). */
size_t ks_operator_lists_count(const struct ks_operator *o);

/* Re-reads the files of a "lists" operator now if they changed, as the
 * periodic monitor does. For tests. */
void ks_operator_lists_poll(struct ks_operator *o);

#endif
