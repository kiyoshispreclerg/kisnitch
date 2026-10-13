/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/rule/rule.go and operator.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Where upstream would panic (an operator type whose callback can't take the
 * operand's value, e.g. "network" on "dest.ip", or an uncompiled operator
 * nested two lists deep), the operator doesn't match instead.
 */
#include "daemon/rules/rule.h"

#include <net/if.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/unicode.h"
#include "daemon/rules/aliases.h"
#include "daemon/rules/lists.h"
#include "daemon/rules/regex.h"

/* ---- schema ----------------------------------------------------------- */

static const struct ks_schema operator_schema;

static const struct ks_field operator_fields[] = {
    KS_FIELD(struct ks_operator, "operand", KS_T_STRING, operand),
    KS_FIELD(struct ks_operator, "data", KS_T_STRING, data),
    KS_FIELD(struct ks_operator, "type", KS_T_STRING, type),
    KS_FIELD_SUB(struct ks_operator, "list", KS_T_ARRAY, list, operator_schema),
    KS_FIELD(struct ks_operator, "sensitive", KS_T_BOOL, sensitive),
};
static const struct ks_schema operator_schema =
    KS_SCHEMA("rule.Operator", struct ks_operator, operator_fields);

static const struct ks_field rule_fields[] = {
    KS_FIELD(struct ks_rule, "created", KS_T_STRING, created),
    KS_FIELD(struct ks_rule, "updated", KS_T_STRING, updated),
    KS_FIELD(struct ks_rule, "name", KS_T_STRING, name),
    KS_FIELD(struct ks_rule, "description", KS_T_STRING, description),
    KS_FIELD(struct ks_rule, "action", KS_T_STRING, action),
    KS_FIELD(struct ks_rule, "duration", KS_T_STRING, duration),
    KS_FIELD_SUB(struct ks_rule, "operator", KS_T_STRUCT, operator, operator_schema),
    KS_FIELD(struct ks_rule, "enabled", KS_T_BOOL, enabled),
    KS_FIELD(struct ks_rule, "precedence", KS_T_BOOL, precedence),
    KS_FIELD(struct ks_rule, "nolog", KS_T_BOOL, nolog),
};
static const struct ks_schema rule_schema =
    KS_SCHEMA("rule.Rule", struct ks_rule, rule_fields);

/* ---- compiled state --------------------------------------------------- */

enum cb {
    CB_NONE,          /* not compiled, or a "list" (no callback upstream) */
    CB_SIMPLE,        /* simpleCmp */
    CB_HASH,          /* hashCmp */
    CB_REGEXP,        /* reCmp */
    CB_NETWORK,       /* cmpNetwork */
    CB_ALIAS,         /* closure over AliasIPCache[data] */
    CB_LISTS_DOMAINS, /* domainsListsCmp */
    CB_LISTS_REGEXP,  /* reListCmp */
    CB_LISTS_SIMPLE,  /* simpleListsCmp */
    CB_LISTS_NETS,    /* ipNetCmp */
};

struct ks_op_state {
    enum cb cb;
    bool compiled; /* isCompiled */
    struct ks_regex *re;
    struct ks_ipnet net;
    struct ks_ipnet *alias_nets;
    size_t nalias;
    struct ks_lists *lists;
};

static void free_state(struct ks_op_state *st)
{
    if (st == NULL)
        return;
    ks_regex_free(st->re);
    free(st->alias_nets);
    ks_lists_free(st->lists);
    free(st);
}

void ks_operator_reset(struct ks_operator *o)
{
    free_state(o->st);
    o->st = NULL;
    for (size_t i = 0; i < o->list.len; i++)
        ks_operator_reset(KS_ARRAY_ITEM(o->list, struct ks_operator, i));
}

void ks_operator_clear(struct ks_operator *o)
{
    ks_operator_reset(o);
    ks_schema_free(&operator_schema, o);
    memset(o, 0, sizeof(*o));
}

/* ---- rules ------------------------------------------------------------ */

void ks_rule_free(struct ks_rule *r)
{
    if (r == NULL)
        return;
    ks_operator_reset(&r->operator);
    ks_schema_free(&rule_schema, r);
    free(r);
}

struct ks_rule *ks_rule_parse(const char *json, size_t len, char *err,
                              size_t errlen)
{
    struct ks_rule *r = malloc(sizeof(*r));
    if (r == NULL) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    if (ks_schema_decode_buf(&rule_schema, json, len, r, err, errlen) < 0) {
        free(r);
        return NULL;
    }
    return r;
}

char *ks_rule_to_json(const struct ks_rule *r)
{
    cJSON *root = ks_schema_encode(&rule_schema, r);
    if (root == NULL)
        return NULL;
    char *out = ks_json_print_go(root, true);
    cJSON_Delete(root);
    return out;
}

struct ks_rule *ks_rule_copy(const struct ks_rule *r)
{
    struct ks_rule *c = malloc(sizeof(*c));
    if (c == NULL)
        return NULL;
    if (ks_schema_copy(&rule_schema, c, r) < 0) {
        free(c);
        return NULL;
    }
    return c;
}

/* time.Now().Format(time.RFC3339): local time, "Z" or "+hh:mm". */
void ks_rfc3339_now(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm tm;
    char zone[16];
    localtime_r(&now, &tm);
    size_t n = strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
    if (strftime(zone, sizeof(zone), "%z", &tm) != 5 ||
        strcmp(zone + 1, "0000") == 0)
        snprintf(buf + n, len - n, "Z");
    else
        snprintf(buf + n, len - n, "%c%c%c:%c%c", zone[0], zone[1], zone[2],
                 zone[3], zone[4]);
}

struct ks_rule *ks_rule_create(const char *name, const char *description,
                               bool enabled, bool precedence, bool nolog,
                               const char *action, const char *duration,
                               const struct ks_operator *op)
{
    struct ks_rule *r = calloc(1, sizeof(*r));
    char created[64];
    if (r == NULL)
        return NULL;
    ks_rfc3339_now(created, sizeof(created));
    r->enabled = enabled;
    r->precedence = precedence;
    r->nolog = nolog;
    if ((r->created = strdup(created)) == NULL ||
        (r->updated = strdup("")) == NULL ||
        (r->name = strdup(name)) == NULL ||
        (r->description = strdup(description)) == NULL ||
        (r->action = strdup(action)) == NULL ||
        (r->duration = strdup(duration)) == NULL ||
        ks_schema_copy(&operator_schema, &r->operator, op) < 0) {
        ks_rule_free(r);
        return NULL;
    }
    return r;
}

void ks_operator_describe(const struct ks_operator *o, char *buf, size_t len)
{
    bool re = o->type != NULL && strcmp(o->type, KS_TYPE_REGEXP) == 0;
    snprintf(buf, len, "%s %s '%s'", o->operand ? o->operand : "", re ? "matches" : "is",
             o->data ? o->data : "");
}

void ks_rule_describe(const struct ks_rule *r, char *buf, size_t len)
{
    char op[512];
    ks_operator_describe(&r->operator, op, sizeof(op));
    snprintf(buf, len, "[%s] %s: if(%s){ %s %s }", r->enabled ? "Enabled" : "Disabled",
             r->name ? r->name : "", op, r->action ? r->action : "",
             r->duration ? r->duration : "");
}

int ks_operator_list_parse(const char *json, struct ks_array *out, char *err,
                           size_t errlen)
{
    char perr[200];
    memset(out, 0, sizeof(*out));
    cJSON *root = ks_json_parse(json, strlen(json), perr, sizeof(perr));
    if (root == NULL) {
        snprintf(err, errlen, "%s", perr);
        return -1;
    }
    int ret = ks_schema_decode_array(&operator_schema, root, out, err, errlen);
    cJSON_Delete(root);
    return ret;
}

/* ---- Compile ---------------------------------------------------------- */

static bool eq(const char *a, const char *b)
{
    return a != NULL && strcmp(a, b) == 0;
}

static int set_str(char **dst, const char *src, char *err, size_t errlen)
{
    char *dup = strdup(src);
    if (dup == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    free(*dst);
    *dst = dup;
    return 0;
}

int ks_operator_compile(struct ks_operator *o, const struct ks_rules_env *env,
                        char *err, size_t errlen)
{
    const char *type = o->type ? o->type : "";
    const char *operand = o->operand ? o->operand : "";
    const char *data = o->data ? o->data : "";

    if (o->st != NULL && o->st->compiled)
        return 0;

    /* Only simple, regexp and list operators may have empty data (to match
     * empty values, or because the list lives in "list"). */
    if (!(eq(type, KS_TYPE_SIMPLE) || eq(type, KS_TYPE_REGEXP) ||
          eq(type, KS_TYPE_LIST)) &&
        !eq(operand, KS_OP_TRUE) && data[0] == '\0') {
        snprintf(err, errlen, "Operand %s cannot be empty (%s)", operand, type);
        return -1;
    }

    if (o->st == NULL && (o->st = calloc(1, sizeof(*o->st))) == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    struct ks_op_state *st = o->st;

    if (eq(type, KS_TYPE_SIMPLE)) {
        if (eq(operand, KS_OP_USER_NAME)) {
            /* user.Lookup; Data becomes the UID. Upstream returns before
             * marking the operator compiled, so this runs on every Compile. */
            struct passwd pw, *res = NULL;
            char buf[4096];
            if (getpwnam_r(data, &pw, buf, sizeof(buf), &res) != 0 || res == NULL) {
                snprintf(err, errlen, "user.name Operand error: user: unknown user %s",
                         data);
                return -1;
            }
            char uid[24];
            snprintf(uid, sizeof(uid), "%u", (unsigned)pw.pw_uid);
            if (set_str(&o->data, uid, err, errlen) < 0)
                return -1;
            st->cb = CB_SIMPLE;
            return 0;
        }
        if (eq(operand, KS_OP_PROCESS_HASH_MD5) || eq(operand, KS_OP_PROCESS_HASH_SHA1)) {
            st->cb = CB_HASH;
            return 0;
        }
        st->cb = CB_SIMPLE;
    } else if (eq(type, KS_TYPE_REGEXP)) {
        st->cb = CB_REGEXP;
        if (!o->sensitive) {
            /* Upstream lowercases the pattern itself (so the rule is saved
             * lowercased, and escapes like \D turn into \d). */
            char *lower = ks_str_to_lower(data);
            if (lower == NULL) {
                snprintf(err, errlen, "out of memory");
                return -1;
            }
            free(o->data);
            o->data = lower;
            data = lower;
        }
        ks_regex_free(st->re);
        st->re = ks_regex_compile(data, err, errlen);
        if (st->re == NULL)
            return -1;
    } else if (eq(type, KS_TYPE_LIST)) {
        if (set_str(&o->operand, KS_OP_LIST, err, errlen) < 0)
            return -1;
        st->cb = CB_NONE;
    } else if (eq(type, KS_TYPE_NETWORK)) {
        const struct ks_alias *al = env ? ks_aliases_find(env->aliases, data) : NULL;
        if (al != NULL) {
            free(st->alias_nets);
            st->alias_nets = NULL;
            st->nalias = 0;
            if (al->nnets > 0) {
                st->alias_nets = malloc(al->nnets * sizeof(*st->alias_nets));
                if (st->alias_nets == NULL) {
                    snprintf(err, errlen, "out of memory");
                    return -1;
                }
                memcpy(st->alias_nets, al->nets, al->nnets * sizeof(*al->nets));
                st->nalias = al->nnets;
            }
            st->cb = CB_ALIAS;
        } else {
            char perr[200];
            if (ks_parse_cidr(data, &st->net, perr, sizeof(perr)) < 0) {
                snprintf(err, errlen, "CIDR parsing error: %s", perr);
                return -1;
            }
            st->cb = CB_NETWORK;
        }
    } else if (eq(type, KS_TYPE_LISTS)) {
        enum ks_lists_kind kind;
        enum cb cb;
        if (eq(operand, KS_OP_DOMAINS_LISTS)) {
            kind = KS_LISTS_DOMAINS;
            cb = CB_LISTS_DOMAINS;
        } else if (eq(operand, KS_OP_DOMAINS_REGEXP_LISTS)) {
            kind = KS_LISTS_REGEXP;
            cb = CB_LISTS_REGEXP;
        } else if (eq(operand, KS_OP_IP_LISTS) || eq(operand, KS_OP_HASH_MD5_LISTS)) {
            kind = KS_LISTS_SIMPLE;
            cb = CB_LISTS_SIMPLE;
        } else if (eq(operand, KS_OP_NET_LISTS)) {
            kind = KS_LISTS_NETS;
            cb = CB_LISTS_NETS;
        } else {
            snprintf(err, errlen, "Unknown Lists operand %s", operand);
            return -1;
        }
        ks_info("loading domains lists: %s, %s, %s", type, operand, data);
        if (st->lists == NULL &&
            (st->lists = ks_lists_new(kind, data, env ? env->loop : NULL)) == NULL) {
            snprintf(err, errlen, "out of memory");
            return -1;
        }
        st->cb = cb;
    } else {
        snprintf(err, errlen, "Unknown Operator type %s", type);
        return -1;
    }

    ks_debug("Operator compiled: %s %s '%s'", o->operand,
             eq(type, KS_TYPE_REGEXP) ? "matches" : "is", o->data);
    st->compiled = true;
    return 0;
}

size_t ks_operator_lists_count(const struct ks_operator *o)
{
    return o->st != NULL && o->st->lists != NULL ? ks_lists_count(o->st->lists) : 0;
}

void ks_operator_lists_poll(struct ks_operator *o)
{
    if (o->st != NULL && o->st->lists != NULL)
        ks_lists_poll(o->st->lists);
}

/* ---- Match ------------------------------------------------------------ */

/* The interface{} upstream passes to callbacks: a string or a net.IP. */
struct value {
    const char *str;         /* NULL if it's an IP */
    const struct ks_ip *ip;  /* NULL if it's a string */
};

static struct value sval(const char *s)
{
    struct value v = {s != NULL ? s : "", NULL};
    return v;
}

static struct value ipval(const struct ks_ip *ip)
{
    struct value v = {NULL, ip};
    return v;
}

/* Insensitive compares lowercase the value, like strings.ToLower. */
static bool lowered_match(struct ks_regex *re, const char *s, bool sensitive)
{
    if (sensitive)
        return ks_regex_match(re, s) == 1;
    char *lower = ks_str_to_lower(s);
    if (lower == NULL)
        return false;
    bool m = ks_regex_match(re, lower) == 1;
    free(lower);
    return m;
}

static bool call_cb(const struct ks_operator *o, struct value v)
{
    const struct ks_op_state *st = o->st;
    const char *data = o->data ? o->data : "";

    if (st == NULL)
        return false; /* nil callback: upstream panics */
    /* A failed Compile leaves upstream's callback set with no regexp, and a
     * stopped "lists" operator has no lists: neither matches anything. */
    if ((st->cb == CB_REGEXP && st->re == NULL) ||
        (st->cb >= CB_LISTS_DOMAINS && st->lists == NULL))
        return false;

    switch (st->cb) {
    case CB_NONE:
        return false;
    case CB_SIMPLE:
        if (v.str == NULL)
            return false;
        return o->sensitive ? strcmp(v.str, data) == 0
                            : ks_str_equal_fold(v.str, data);
    case CB_HASH:
        if (v.str == NULL)
            return false;
        if (v.str[0] == '\0')
            return true; /* fake a match to avoid displaying a pop-up */
        return strcmp(v.str, data) == 0;
    case CB_REGEXP:
        if (v.str == NULL) {
            ks_warning("Operator.reCmp() bad interface type: net.IP");
            return false;
        }
        return lowered_match(st->re, v.str, o->sensitive);
    case CB_NETWORK:
        return v.ip != NULL && ks_ipnet_contains(&st->net, v.ip);
    case CB_ALIAS:
        if (v.ip == NULL)
            return false;
        for (size_t i = 0; i < st->nalias; i++)
            if (ks_ipnet_contains(&st->alias_nets[i], v.ip))
                return true;
        return false;
    case CB_LISTS_DOMAINS: {
        if (v.str == NULL || v.str[0] == '\0')
            return false;
        if (o->sensitive)
            return ks_lists_has(st->lists, v.str);
        char *lower = ks_str_to_lower(v.str);
        bool m = lower != NULL && ks_lists_has(st->lists, lower);
        free(lower);
        return m;
    }
    case CB_LISTS_SIMPLE:
        if (v.str == NULL || v.str[0] == '\0')
            return false;
        return ks_lists_has(st->lists, v.str);
    case CB_LISTS_NETS:
        return v.ip != NULL && ks_lists_match_net(st->lists, v.ip);
    case CB_LISTS_REGEXP: {
        if (v.str == NULL || v.str[0] == '\0')
            return false;
        if (o->sensitive)
            return ks_lists_match_regexp(st->lists, v.str);
        char *lower = ks_str_to_lower(v.str);
        bool m = lower != NULL && ks_lists_match_regexp(st->lists, lower);
        free(lower);
        return m;
    }
    }
    return false;
}

static bool match_str(const struct ks_operator *o, const char *s)
{
    return call_cb(o, sval(s));
}

static bool match_uint(const struct ks_operator *o, unsigned long long n)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "%llu", n);
    return match_str(o, buf);
}

static bool match_int(const struct ks_operator *o, long long n)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "%lld", n);
    return match_str(o, buf);
}

static bool match_ipstr(const struct ks_operator *o, const struct ks_ip *ip)
{
    char buf[KS_IP_STRLEN];
    ks_ip_string(ip, buf, sizeof(buf));
    return match_str(o, buf);
}

static bool match_iface(const struct ks_operator *o, int idx)
{
    char name[IF_NAMESIZE];
    if (idx <= 0 || if_indextoname((unsigned)idx, name) == NULL)
        return false;
    return match_str(o, name);
}

/* core.Trim on the env var name. */
static void trim_name(const char *s, char *out, size_t len)
{
    while (*s == '\r' || *s == '\n' || *s == '\t' || *s == ' ')
        s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == '\t' ||
                     s[n - 1] == ' '))
        n--;
    snprintf(out, len, "%.*s", (int)n, s);
}

static const struct ks_process empty_process = {0};

bool ks_operator_match(const struct ks_operator *o, const struct ks_conn *c,
                       bool has_checksums)
{
    const char *op = o->operand ? o->operand : "";

    if (strcmp(op, KS_OP_TRUE) == 0)
        return true;
    if (strcmp(op, KS_OP_LIST) == 0) {
        /* listMatch: res = res && item.Match() for every item, so an empty
         * list matches. */
        for (size_t i = 0; i < o->list.len; i++)
            if (!ks_operator_match(KS_ARRAY_ITEM(o->list, struct ks_operator, i),
                                   c, has_checksums))
                return false;
        return true;
    }
    if (c == NULL)
        return false;
    const struct ks_process *p = c->process ? c->process : &empty_process;

    if (strcmp(op, KS_OP_PROCESS_PATH) == 0)
        return match_str(o, p->path);
    if (strcmp(op, KS_OP_PROCESS_PARENT_PATH) == 0) {
        for (const struct ks_process *pp = p->parent; pp != NULL; pp = pp->parent)
            if (match_str(o, pp->path))
                return true;
        return false;
    }
    if (strcmp(op, KS_OP_PROCESS_CMD) == 0) {
        size_t len = 1;
        for (size_t i = 0; i < p->nargs; i++)
            len += strlen(p->args[i]) + 1;
        char *cmd = malloc(len);
        if (cmd == NULL)
            return false;
        size_t o2 = 0;
        cmd[0] = '\0';
        for (size_t i = 0; i < p->nargs; i++) {
            size_t n = strlen(p->args[i]);
            if (i > 0)
                cmd[o2++] = ' ';
            memcpy(cmd + o2, p->args[i], n);
            o2 += n;
        }
        cmd[o2] = '\0';
        bool m = match_str(o, cmd);
        free(cmd);
        return m;
    }
    if (strcmp(op, KS_OP_DST_HOST) == 0)
        return match_str(o, c->dst_host);
    if (strcmp(op, KS_OP_DST_IP) == 0)
        return match_ipstr(o, &c->dst_ip);
    if (strcmp(op, KS_OP_DST_PORT) == 0)
        return match_uint(o, c->dst_port);
    if (strcmp(op, KS_OP_DOMAINS_LISTS) == 0)
        return match_str(o, c->dst_host);
    if (strcmp(op, KS_OP_IP_LISTS) == 0)
        return match_ipstr(o, &c->dst_ip);
    if (strcmp(op, KS_OP_HASH_MD5_LISTS) == 0)
        return match_str(o, p->checksum_md5);
    if (strcmp(op, KS_OP_USER_ID) == 0 || strcmp(op, KS_OP_USER_NAME) == 0)
        return match_int(o, c->uid);
    if (strcmp(op, KS_OP_DST_NETWORK) == 0)
        return call_cb(o, ipval(&c->dst_ip));
    if (strcmp(op, KS_OP_SRC_NETWORK) == 0)
        return call_cb(o, ipval(&c->src_ip));
    if (strcmp(op, KS_OP_NET_LISTS) == 0)
        return call_cb(o, ipval(&c->dst_ip));
    if (strcmp(op, KS_OP_DOMAINS_REGEXP_LISTS) == 0)
        return match_str(o, c->dst_host);
    if (strcmp(op, KS_OP_IFACE_IN) == 0)
        return match_iface(o, c->iface_in);
    if (strcmp(op, KS_OP_IFACE_OUT) == 0)
        return match_iface(o, c->iface_out);
    if (strcmp(op, KS_OP_PROCESS_HASH_MD5) == 0 ||
        strcmp(op, KS_OP_PROCESS_HASH_SHA1) == 0) {
        /* True when checksums are off or none was computed; otherwise true
         * if any computed checksum matches. */
        if (!has_checksums)
            return true;
        bool ret = true;
        const char *sums[2] = {p->checksum_md5, p->checksum_sha1};
        for (int i = 0; i < 2; i++) {
            if (sums[i] == NULL)
                continue;
            ret = match_str(o, sums[i]);
            if (ret)
                break;
        }
        return ret;
    }
    if (strcmp(op, KS_OP_PROTO) == 0)
        return match_str(o, c->protocol);
    if (strcmp(op, KS_OP_SRC_IP) == 0)
        return match_ipstr(o, &c->src_ip);
    if (strcmp(op, KS_OP_SRC_PORT) == 0)
        return match_uint(o, c->src_port);
    if (strcmp(op, KS_OP_PROCESS_ID) == 0)
        return match_int(o, p->pid);
    if (strncmp(op, KS_OP_PROCESS_ENV_PREFIX, strlen(KS_OP_PROCESS_ENV_PREFIX)) == 0) {
        char name[256];
        trim_name(op + strlen(KS_OP_PROCESS_ENV_PREFIX), name, sizeof(name));
        const char *value = "";
        for (size_t i = 0; i < p->nenv; i++)
            if (strcmp(p->env[i].name, name) == 0)
                value = p->env[i].value;
        return match_str(o, value);
    }
    return false;
}
