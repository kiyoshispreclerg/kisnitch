/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/firewall/ and the widget-free logic of
 * ui/opensnitch/dialogs/firewall_rule.py.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/fwrules.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- enums ------------------------------------------------------------- */

const char *const ks_fw_verdicts[] = {"",      "accept", "drop",     "reject", "return", "queue",
                                      "dnat",  "snat",   "redirect", "tproxy", "stop"};
const char *const ks_fw_operators[] = {"==", "!=", ">=", ">", "<=", "<"};
const char *const ks_fw_port_protocols[] = {"tcp,udp", "tcp", "udp", "udplite", "sctp", "dccp"};
const char *const ks_fw_protocols[] = {"tcp", "udp",  "udplite", "sctp", "dccp",  "icmp",
                                       "icmpv6", "ah", "ethernet", "gre", "ip",   "ipip",
                                       "l2tp", "comp", "igmp", "esp", "raw", "encap"};
const char *const ks_fw_families[] = {"inet", "ip", "ip6"};
const char *const ks_fw_expr_meta[] = {"set",   "mark",     "l4proto", "skuid",
                                       "skgid", "protocol", "priority"};
const char *const ks_fw_icmp_types[] = {
    "echo-request",         "echo-reply",          "source-quench",
    "destination-unreachable", "router-advertisement", "router-solicitation",
    "redirect",             "time-exceeded",       "info-request",
    "info-reply",           "parameter-problem",   "timestamp-request",
    "timestamp-reply",      "address-mask-request", "address-mask-reply",
    "packet-too-big",       "neighbour-solicitation", "neighbour-advertisement"};
const char *const ks_fw_log_levels[] = {"emerg",  "alert", "crit",  "err",  "warn",
                                        "notice", "info",  "debug", "audit"};
const char *const ks_fw_rate_units[] = {"bytes", "kbytes", "mbytes", "gbytes"};
const char *const ks_fw_time_units[] = {"second", "minute", "hour", "day"};

int ks_fw_index_of(const char *const *list, size_t n, const char *v)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(list[i], v) == 0)
            return (int)i;
    return -1;
}

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

static bool ieq(const char *a, const char *b)
{
    a = nz(a);
    b = nz(b);
    for (; *a && *b; a++, b++) {
        char x = *a >= 'A' && *a <= 'Z' ? (char)(*a - 'A' + 'a') : *a;
        if (x != *b)
            return false;
    }
    return *a == *b;
}

static bool seq(const char *a, const char *b)
{
    return strcmp(nz(a), nz(b)) == 0;
}

/* ---- chains and rules ----------------------------------------------- */

void ks_fwr_free_chain(struct ks_fw_chain *c)
{
    ks_schema_free(&ks_fw_chain_schema, c);
}

int ks_fwr_copy_chain(struct ks_fw_chain *dst, const struct ks_fw_chain *src)
{
    return ks_schema_copy(&ks_fw_chain_schema, dst, src);
}

static int copy_rule(struct ks_fw_rule *dst, const struct ks_fw_rule *src)
{
    return ks_schema_copy(&ks_fw_rule_schema, dst, src);
}

#define FOR_CHAINS(fw, c)                                                          \
    for (size_t i_ = 0; i_ < (fw)->system_rules.len; i_++)                          \
        for (size_t j_ = 0; j_ < KS_SYSFW_RULES(fw, i_)->chains.len; j_++)          \
            for (struct ks_fw_chain *c = KS_SYSFW_CHAIN(KS_SYSFW_RULES(fw, i_), j_); \
                 c != NULL; c = NULL)

struct ks_fw_rule *ks_fwr_find(struct ks_sysfw *fw, const char *uuid, struct ks_fw_chain **chain)
{
    FOR_CHAINS(fw, c) {
        for (size_t k = 0; k < c->rules.len; k++) {
            struct ks_fw_rule *r = KS_SYSFW_RULE(c, k);
            if (seq(r->uuid, uuid)) {
                if (chain != NULL)
                    *chain = c;
                return r;
            }
        }
    }
    return NULL;
}

/* Rules.new_flat: the chain without its rules, plus `r`. */
static int new_flat(struct ks_fw_chain *out, const struct ks_fw_chain *c, const struct ks_fw_rule *r)
{
    struct ks_fw_chain tmp = *c;
    tmp.rules.items = NULL;
    tmp.rules.len = 0;
    if (ks_fwr_copy_chain(out, &tmp) < 0)
        return -1;
    out->rules.items = calloc(1, sizeof(struct ks_fw_rule));
    if (out->rules.items == NULL || copy_rule(out->rules.items, r) < 0) {
        ks_fwr_free_chain(out);
        return -1;
    }
    out->rules.len = 1;
    out->rules.non_nil = true;
    return 0;
}

int ks_fwr_flat_by_uuid(struct ks_sysfw *fw, const char *uuid, struct ks_fw_chain *out)
{
    if (uuid == NULL || uuid[0] == '\0')
        return -1;
    struct ks_fw_chain *c;
    struct ks_fw_rule *r = ks_fwr_find(fw, uuid, &c);
    return r != NULL ? new_flat(out, c, r) : -1;
}

static bool same_chain(const struct ks_fw_chain *a, const struct ks_fw_chain *b)
{
    return seq(a->name, b->name) && seq(a->hook, b->hook) && seq(a->table, b->table) &&
           seq(a->family, b->family) && seq(a->type, b->type);
}

/* The rules serialize to the same protobuf, UUIDs aside. */
static bool rules_equal(const struct ks_fw_rule *a, const struct ks_fw_rule *b)
{
    if (!seq(a->table, b->table) || !seq(a->chain, b->chain) || a->enabled != b->enabled ||
        a->position != b->position || !seq(a->description, b->description) ||
        !seq(a->parameters, b->parameters) || !seq(a->target, b->target) ||
        !seq(a->target_parameters, b->target_parameters) ||
        a->expressions.len != b->expressions.len)
        return false;
    for (size_t i = 0; i < a->expressions.len; i++) {
        const struct ks_fw_statement *x = KS_SYSFW_EXPR(a, i)->statement;
        const struct ks_fw_statement *y = KS_SYSFW_EXPR(b, i)->statement;
        if ((x == NULL) != (y == NULL))
            return false;
        if (x == NULL)
            continue;
        if (!seq(x->op, y->op) || !seq(x->name, y->name) || x->values.len != y->values.len)
            return false;
        for (size_t j = 0; j < x->values.len; j++)
            if (!seq(KS_SYSFW_VALUE(x, j)->key, KS_SYSFW_VALUE(y, j)->key) ||
                !seq(KS_SYSFW_VALUE(x, j)->value, KS_SYSFW_VALUE(y, j)->value))
                return false;
    }
    return true;
}

bool ks_fwr_is_duplicated(struct ks_sysfw *fw, const struct ks_fw_chain *flat)
{
    if (flat->rules.len == 0)
        return false;
    const struct ks_fw_rule *nr = KS_SYSFW_RULE(flat, 0);
    FOR_CHAINS(fw, c) {
        if (!same_chain(c, flat))
            continue;
        for (size_t k = 0; k < c->rules.len; k++) {
            const struct ks_fw_rule *r = KS_SYSFW_RULE(c, k);
            if (rules_equal(r, nr) || seq(nr->uuid, r->uuid))
                return true;
        }
    }
    return false;
}

static int chain_put(struct ks_fw_chain *c, const struct ks_fw_rule *r, size_t pos)
{
    struct ks_fw_rule *v = realloc(c->rules.items, (c->rules.len + 1) * sizeof(*v));
    if (v == NULL)
        return -1;
    c->rules.items = v;
    if (pos > c->rules.len)
        pos = c->rules.len;
    memmove(&v[pos + 1], &v[pos], (c->rules.len - pos) * sizeof(*v));
    if (copy_rule(&v[pos], r) < 0) {
        memmove(&v[pos], &v[pos + 1], (c->rules.len - pos) * sizeof(*v));
        return -1;
    }
    c->rules.len++;
    c->rules.non_nil = true;
    return 0;
}

static int add_at(struct ks_sysfw *fw, const struct ks_fw_chain *flat, size_t pos, bool append,
                  const char **err, const char *dup_msg)
{
    if (ks_fwr_is_duplicated(fw, flat)) {
        *err = dup_msg;
        return -1;
    }
    FOR_CHAINS(fw, c) {
        if (!same_chain(c, flat))
            continue;
        if (chain_put(c, KS_SYSFW_RULE(flat, 0), append ? c->rules.len : pos) < 0) {
            *err = "out of memory";
            return -1;
        }
        return 0;
    }
    *err = "firewall table/chain not properly configured.";
    return -1;
}

int ks_fwr_add(struct ks_sysfw *fw, const struct ks_fw_chain *flat, const char **err)
{
    if (fw == NULL || flat->rules.len == 0) {
        *err = "rule not found by its ID.";
        return -1;
    }
    return add_at(fw, flat, 0, true, err, "duplicated.");
}

int ks_fwr_insert(struct ks_sysfw *fw, const struct ks_fw_chain *flat, size_t position,
                  const char **err)
{
    if (fw == NULL || flat->rules.len == 0) {
        *err = "this node doesn't have a firewall configuration, review it.";
        return -1;
    }
    return add_at(fw, flat, position, false, err, "duplicated");
}

int ks_fwr_update(struct ks_sysfw *fw, const char *uuid, const struct ks_fw_chain *flat,
                  const char **err)
{
    if (fw == NULL || flat->rules.len == 0) {
        *err = "this node doesn't have a firewall configuration, review it.";
        return -1;
    }
    struct ks_fw_rule *r = ks_fwr_find(fw, uuid, NULL);
    if (r == NULL) {
        *err = "rule not found by its ID.";
        return -1;
    }
    struct ks_fw_rule n;
    if (copy_rule(&n, KS_SYSFW_RULE(flat, 0)) < 0) {
        *err = "out of memory";
        return -1;
    }
    ks_schema_free(&ks_fw_rule_schema, r);
    *r = n;
    return 0;
}

int ks_fwr_delete(struct ks_sysfw *fw, const char *uuid)
{
    if (fw == NULL)
        return -1;
    struct ks_fw_chain *c;
    struct ks_fw_rule *r = ks_fwr_find(fw, uuid, &c);
    if (r == NULL)
        return -1;
    size_t idx = (size_t)(r - (struct ks_fw_rule *)c->rules.items);
    ks_schema_free(&ks_fw_rule_schema, r);
    memmove(r, r + 1, (c->rules.len - idx - 1) * sizeof(*r));
    c->rules.len--;
    return 0;
}

bool ks_fwr_swap(struct ks_sysfw *fw, const char *uuid, size_t old_pos, size_t new_pos)
{
    struct ks_fw_chain *c;
    if (fw == NULL || ks_fwr_find(fw, uuid, &c) == NULL || old_pos >= c->rules.len ||
        new_pos >= c->rules.len)
        return false;
    struct ks_fw_rule *v = c->rules.items, t = v[old_pos];
    v[old_pos] = v[new_pos];
    v[new_pos] = t;
    return true;
}

int ks_fwr_enable(struct ks_sysfw *fw, const char *uuid, bool enable)
{
    struct ks_fw_rule *r = fw != NULL ? ks_fwr_find(fw, uuid, NULL) : NULL;
    if (r == NULL || uuid == NULL || uuid[0] == '\0')
        return -1;
    r->enabled = enable;
    return 0;
}

int ks_fwr_set_target(struct ks_sysfw *fw, const char *uuid, const char *target)
{
    struct ks_fw_rule *r = fw != NULL ? ks_fwr_find(fw, uuid, NULL) : NULL;
    char *t;
    if (r == NULL || uuid == NULL || uuid[0] == '\0' || (t = strdup(target)) == NULL)
        return -1;
    free(r->target);
    r->target = t;
    return 0;
}

const char *ks_fwr_get_policy(const struct ks_sysfw *fw, const char *hook, const char *type,
                              const char *family)
{
    if (fw == NULL)
        return NULL;
    FOR_CHAINS(fw, c)
        if (ieq(c->hook, hook) && ieq(c->type, type) && ieq(c->family, family))
            return nz(c->policy);
    return NULL;
}

/* ---- to_array, filter_rules --------------------------------------------- */

struct sb {
    char *p;
    size_t len, cap;
    bool oom;
};

static void sb_add(struct sb *b, const char *s)
{
    size_t n = strlen(s);
    if (b->oom)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 64;
        while (b->len + n + 1 > cap)
            cap *= 2;
        char *np = realloc(b->p, cap);
        if (np == NULL) {
            b->oom = true;
            return;
        }
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->len, s, n + 1);
    b->len += n;
}

static char *sb_take(struct sb *b)
{
    if (b->oom) {
        free(b->p);
        return NULL;
    }
    return b->p != NULL ? b->p : strdup("");
}

int ks_fwr_to_array(const char *addr, const struct ks_fw_chain *c, const struct ks_fw_rule *r,
                    char *cols[KS_FWR_NCOLS])
{
    const char *plain[] = {r->uuid, addr, c->name, c->table, c->family, c->hook,
                           r->enabled ? "True" : "False", r->description};
    memset(cols, 0, KS_FWR_NCOLS * sizeof(*cols));
    for (size_t i = 0; i < 8; i++)
        if ((cols[i] = strdup(nz(plain[i]))) == NULL)
            goto oom;
    struct sb b = {0};
    for (size_t i = 0; i < r->expressions.len; i++) {
        const struct ks_fw_statement *st = KS_SYSFW_EXPR(r, i)->statement;
        if (st == NULL)
            continue;
        /* "{name} " + "{key} {op }{value} " for each value; op is
         * omitted only when it's "==" */
        sb_add(&b, nz(st->name));
        sb_add(&b, " ");
        for (size_t j = 0; j < st->values.len; j++) {
            const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, j);
            sb_add(&b, nz(v->key));
            sb_add(&b, " ");
            if (strcmp(nz(st->op), "==") != 0) {
                sb_add(&b, nz(st->op));
                sb_add(&b, " ");
            }
            if (strcmp(nz(v->key), "prefix") == 0) {
                sb_add(&b, "\"");
                sb_add(&b, nz(v->value));
                sb_add(&b, "\"");
            } else {
                sb_add(&b, nz(v->value));
            }
            sb_add(&b, " ");
        }
    }
    if ((cols[8] = sb_take(&b)) == NULL || (cols[9] = strdup(nz(r->target))) == NULL ||
        (cols[10] = strdup(nz(r->target_parameters))) == NULL)
        goto oom;
    return 0;
oom:
    for (size_t i = 0; i < KS_FWR_NCOLS; i++) {
        free(cols[i]);
        cols[i] = NULL;
    }
    return -1;
}

static bool has(const char *hay, const char *nail)
{
    return strstr(nz(hay), nail) != NULL;
}

bool ks_fwr_matches(const struct ks_fw_chain *c, const struct ks_fw_rule *r, const char *nail)
{
    if (seq(nail, r->uuid))
        return true;
    if (has(c->family, nail) || has(c->hook, nail) || has(r->description, nail) ||
        has(r->target, nail) || has(r->target_parameters, nail))
        return true;
    for (size_t i = 0; i < r->expressions.len; i++) {
        const struct ks_fw_statement *st = KS_SYSFW_EXPR(r, i)->statement;
        if (st == NULL)
            continue;
        if (has(st->op, nail) || has(st->name, nail))
            return true;
        struct sb b = {0};
        for (size_t j = 0; j < st->values.len; j++) {
            sb_add(&b, nz(KS_SYSFW_VALUE(st, j)->key));
            sb_add(&b, " ");
            sb_add(&b, nz(KS_SYSFW_VALUE(st, j)->value));
        }
        bool m = b.p != NULL && strstr(b.p, nail) != NULL;
        free(b.p);
        if (m)
            return true;
    }
    return false;
}

/* ---- profiles ------------------------------------------------------------- */

static const char profile_drop_input[] =
    "{\"Name\": \"drop-filter-input\", \"Table\": \"opensnitch\", \"Family\": \"inet\", "
    "\"Priority\": \"\", \"Type\": \"filter\", \"Hook\": \"input\", \"Policy\": \"drop\", "
    "\"Rules\": [{\"Table\": \"\", \"Chain\": \"\", \"UUID\": "
    "\"profile-drop-inbound-2d7e6fe4-c21d-11ec-99a6-3c970e298b0c\", \"Enabled\": true, "
    "\"Position\": \"0\", \"Description\": \"[profile-drop-inbound] allow localhost "
    "connections\", \"Parameters\": \"\", \"Expressions\": [{\"Statement\": {\"Op\": \"\", "
    "\"Name\": \"iifname\", \"Values\": [{\"Key\": \"lo\", \"Value\": \"\"}]}}], \"Target\": "
    "\"accept\", \"TargetParameters\": \"\"}, {\"Enabled\": true, \"Description\": "
    "\"[profile-drop-inbound] allow established,related connections\", \"UUID\": "
    "\"profile-drop-inbound-e1fc1a1c-c21c-11ec-9a2a-3c970e298b0c\", \"Expressions\": "
    "[{\"Statement\": {\"Op\": \"\", \"Name\": \"ct\", \"Values\": [{\"Key\": \"state\", "
    "\"Value\": \"related\"}, {\"Key\": \"state\", \"Value\": \"established\"}]}}], "
    "\"Target\": \"accept\", \"TargetParameters\": \"\"}]}";

static const char profile_drop_output[] =
    "{\"Name\": \"drop-mangle-output\", \"Table\": \"opensnitch\", \"Family\": \"inet\", "
    "\"Priority\": \"\", \"Type\": \"mangle\", \"Hook\": \"output\", \"Policy\": \"drop\", "
    "\"Rules\": [{\"Enabled\": true, \"Description\": \"[profile-drop-outbound] allow "
    "established,related connections\", \"UUID\": "
    "\"profile-drop-outbound-e1fc1a1c-c21c-11ec-9a2a-3c970e298b0c\", \"Expressions\": "
    "[{\"Statement\": {\"Op\": \"\", \"Name\": \"ct\", \"Values\": [{\"Key\": \"state\", "
    "\"Value\": \"established,related\"}]}}], \"Target\": \"accept\", "
    "\"TargetParameters\": \"\"}]}";

int ks_fwr_profile(enum ks_fw_profile p, struct ks_fw_chain *out)
{
    char buf[512];
    const char *json = buf;
    switch (p) {
    case KS_FW_PROFILE_DROP_INPUT:
        json = profile_drop_input;
        break;
    case KS_FW_PROFILE_DROP_OUTPUT:
        json = profile_drop_output;
        break;
    default: {
        const char *name = "accept-filter-input", *type = "filter", *hook = "input";
        const char *policy = "accept";
        if (p == KS_FW_PROFILE_ACCEPT_OUTPUT) {
            name = "accept-mangle-output";
            type = "mangle";
            hook = "output";
        } else if (p == KS_FW_PROFILE_ACCEPT_FORWARD || p == KS_FW_PROFILE_DROP_FORWARD) {
            bool drop = p == KS_FW_PROFILE_DROP_FORWARD;
            name = drop ? "drop-mangle-forward" : "accept-mangle-forward";
            type = "mangle";
            hook = "forward";
            policy = drop ? "drop" : "accept";
        }
        snprintf(buf, sizeof(buf),
                 "{\"Name\": \"%s\", \"Table\": \"opensnitch\", \"Family\": \"inet\", "
                 "\"Priority\": \"\", \"Type\": \"%s\", \"Hook\": \"%s\", \"Policy\": \"%s\", "
                 "\"Rules\": []}",
                 name, type, hook, policy);
    }
    }
    char err[256];
    return ks_schema_decode_buf(&ks_fw_chain_schema, json, strlen(json), out, err, sizeof(err));
}

static bool profile_chain(const struct ks_fw_chain *c, const struct ks_fw_chain *p)
{
    return ieq(c->hook, nz(p->hook)) && ieq(c->type, nz(p->type)) &&
           ieq(c->family, nz(p->family)) && ieq(c->table, nz(p->table));
}

int ks_fwr_apply_profile(struct ks_sysfw *fw, const struct ks_fw_chain *profile,
                         const char **err)
{
    if (fw == NULL) {
        *err = "profile not applied";
        return -1;
    }
    FOR_CHAINS(fw, c) {
        if (!profile_chain(c, profile))
            continue;
        char *pol = strdup(nz(profile->policy));
        if (pol == NULL) {
            *err = "out of memory";
            return -1;
        }
        free(c->policy);
        c->policy = pol;
        for (size_t k = 0; k < profile->rules.len; k++) {
            struct ks_fw_chain flat;
            if (new_flat(&flat, c, KS_SYSFW_RULE(profile, k)) < 0) {
                *err = "out of memory";
                return -1;
            }
            const char *e;
            if (!ks_fwr_is_duplicated(fw, &flat))
                ks_fwr_add(fw, &flat, &e);
            ks_fwr_free_chain(&flat);
        }
        return 0;
    }
    *err = "profile not applied";
    return -1;
}

void ks_fwr_delete_profile(struct ks_sysfw *fw, const struct ks_fw_chain *profile)
{
    if (fw == NULL)
        return;
    FOR_CHAINS(fw, c) {
        if (!profile_chain(c, profile))
            continue;
        /* the indexes are taken first, then deleted one by one (an index
         * past the end is the last rule), as upstream does */
        size_t cand[64], ncand = 0;
        for (size_t r = 0; r < c->rules.len; r++)
            for (size_t k = 0; k < profile->rules.len && ncand < 64; k++)
                if (seq(KS_SYSFW_RULE(c, r)->uuid, KS_SYSFW_RULE(profile, k)->uuid))
                    cand[ncand++] = r;
        for (size_t i = 0; i < ncand; i++) {
            size_t rdx = cand[i];
            if (c->rules.len == 0)
                break;
            if (rdx >= c->rules.len)
                rdx = c->rules.len - 1;
            char *uuid = strdup(nz(KS_SYSFW_RULE(c, rdx)->uuid));
            if (uuid != NULL)
                ks_fwr_delete(fw, uuid);
            free(uuid);
        }
    }
}

/* ---- NetworkServices ------------------------------------------------------ */

static bool name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '-';
}

/* re.search(r'([a-zA-Z0-9\-]+)( |\t)+([0-9]+)\/([a-zA-Z0-9\-]+)(.*)\n', line) */
static bool services_match(const char *line, char *name, size_t nlen, char *port, size_t plen,
                           char *proto, size_t prlen)
{
    size_t len = strlen(line);
    if (len == 0 || line[len - 1] != '\n')
        return false;
    for (size_t i = 0; i < len; i++) {
        size_t a = i;
        while (a < len && name_char(line[a]))
            a++;
        if (a == i)
            continue;
        size_t b = a;
        while (b < len && (line[b] == ' ' || line[b] == '\t'))
            b++;
        if (b == a)
            continue;
        size_t d = b;
        while (d < len && line[d] >= '0' && line[d] <= '9')
            d++;
        if (d == b || line[d] != '/')
            continue;
        size_t p = d + 1, q = p;
        while (q < len && name_char(line[q]))
            q++;
        if (q == p)
            continue;
        snprintf(name, nlen, "%.*s", (int)(a - i), line + i);
        snprintf(port, plen, "%.*s", (int)(d - b), line + b);
        snprintf(proto, prlen, "%.*s", (int)(q - p), line + p);
        return true;
    }
    return false;
}

static void services_add(struct ks_fw_services *s, const char *name, const char *port)
{
    char **n = realloc(s->names, (s->n + 1) * sizeof(*n));
    if (n == NULL)
        return;
    s->names = n;
    char **p = realloc(s->ports, (s->n + 1) * sizeof(*p));
    if (p == NULL)
        return;
    s->ports = p;
    s->names[s->n] = strdup(name);
    s->ports[s->n] = strdup(port);
    if (s->names[s->n] == NULL || s->ports[s->n] == NULL) {
        free(s->names[s->n]);
        free(s->ports[s->n]);
        return;
    }
    s->n++;
}

void ks_fw_services_load(struct ks_fw_services *s, const char *path)
{
    memset(s, 0, sizeof(*s));
    if (path == NULL) {
        path = "/etc/services";
        FILE *t = fopen(path, "r");
        if (t == NULL)
            path = "/usr/etc/services";
        else
            fclose(t);
    }
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return;
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#')
            continue;
        char name[256], port[32], proto[64], entry[400];
        if (!services_match(line, name, sizeof(name), port, sizeof(port), proto, sizeof(proto)))
            continue;
        snprintf(entry, sizeof(entry), "%s/%s (%s)", name, port, proto);
        services_add(s, entry, port);
    }
    fclose(f);
    /* extra ports that don't exist in /etc/services */
    services_add(s, "wireguard/51820 WireGuard VPN", "51820");
}

void ks_fw_services_free(struct ks_fw_services *s)
{
    for (size_t i = 0; i < s->n; i++) {
        free(s->names[i]);
        free(s->ports[i]);
    }
    free(s->names);
    free(s->ports);
    memset(s, 0, sizeof(*s));
}

int ks_fw_services_by_name(const struct ks_fw_services *s, const char *name)
{
    return s != NULL ? ks_fw_index_of((const char *const *)s->names, s->n, name) : -1;
}

int ks_fw_services_by_port(const struct ks_fw_services *s, const char *port)
{
    return s != NULL ? ks_fw_index_of((const char *const *)s->ports, s->n, port) : -1;
}

/* ---- the rule dialog ---------------------------------------------------------- */

const char *const ks_fwf_statm_labels[KS_FWF_NSTATM + 1] = {
    "",
    "Dest Port",
    "Source Port",
    "Dest IP",
    "Source IP",
    "Input interface",
    "Output interface",
    "Set conntrack mark",
    "Match conntrack mark",
    "Match conntrack state(s)",
    "Set mark on packet",
    "Match packet information",
    "ICMP",
    "ICMPv6",
    "LOG",
    "Bandwidth quotas",
    "COUNTER",
    "Rate limit connections",
};

/* STATM_CONF: name and keys (NULL values: the key has no value) */
struct statm_key {
    const char *key;
    bool has_values;
};
struct statm_conf {
    const char *name;
    struct statm_key keys[2];
    size_t nkeys;
    const char *tooltip;
};

#define PORT_TIP "\nSupported formats:\n\n - Simple: 23\n - Ranges: 80-1024\n - Multiple ports: 80,443,8080\n"
#define IP_TIP                                                                              \
    "\nSupported formats:\n\n - Simple: 1.2.3.4\n - IP ranges: 1.2.3.100-1.2.3.200\n - "  \
    "Network ranges: 1.2.3.4/24\n"
#define IFACE_TIP                                                                           \
    "Match input interface. Regular expressions not allowed.\nUse * to match multiple " \
    "interfaces."
#define OFACE_TIP                                                                           \
    "Match output interface. Regular expressions not allowed.\nUse * to match multiple " \
    "interfaces."
#define ICMP_TIP(v)                                                                       \
    "\nMatch " v " codes.\n\nSupported formats:\n - Simple: echo-request\n - Multiple " \
    "separated by commas: echo-request,echo-reply\n"

static const struct statm_conf statm_conf[KS_FWF_NSTATM] = {
    [KS_FWF_DPORT] = {"tcp", {{"dport", true}}, 1, PORT_TIP},
    [KS_FWF_SPORT] = {"tcp", {{"sport", true}}, 1, PORT_TIP},
    [KS_FWF_DEST_IP] = {"ip", {{"daddr", true}}, 1, IP_TIP},
    [KS_FWF_SOURCE_IP] = {"ip", {{"saddr", true}}, 1, IP_TIP},
    [KS_FWF_IIFNAME] = {"iifname", {{"", true}}, 1, IFACE_TIP},
    [KS_FWF_OIFNAME] = {"oifname", {{"", true}}, 1, OFACE_TIP},
    [KS_FWF_CT_SET] = {"ct", {{"set", false}, {"mark", true}}, 2,
                       "Set a conntrack mark on the connection, in decimal format."},
    [KS_FWF_CT_MARK] = {"ct", {{"mark", true}}, 1,
                        "Match a conntrack mark of the connection, in decimal format."},
    [KS_FWF_CT_STATE] = {"ct", {{"state", true}}, 1,
                         "Match conntrack states.\n\nSupported formats:\n - Simple: new\n - "
                         "Multiple states separated by commas: related,new\n"},
    [KS_FWF_META_SET_MARK] = {"meta", {{"set", false}, {"mark", true}}, 2,
                              "Set a mark on the packet matching the specified conditions. "
                              "The value is in decimal format."},
    [KS_FWF_META] = {"meta", {{"mark", true}, {"l4proto", true}}, 2,
                     "\nMatch packet's metainformation.\n\nValue must be in decimal format, "
                     "except for the \"l4proto\" option.\nFor l4proto it can be a lower case "
                     "string, for example:\n tcp\n udp\n icmp,\n etc\n\nIf the value is "
                     "decimal for protocol or lproto, it'll use it as the code of\nthat "
                     "protocol.\n"},
    [KS_FWF_ICMP] = {"icmp", {{"type", true}}, 1, ICMP_TIP("ICMP")},
    [KS_FWF_ICMPV6] = {"icmpv6", {{"type", true}}, 1, ICMP_TIP("ICMPv6")},
    [KS_FWF_LOG] = {"log", {{"prefix", true}}, 1,
                    "Print a message when this rule matches a packet."},
    [KS_FWF_QUOTA] = {"quota", {{"over", true}, {"unit", true}}, 2,
                      "\nApply quotas on connections.\n\nFor example when:\n - \"quota over "
                      "10/mbytes\" -> apply the Action defined (DROP)\n - \"quota until "
                      "10/mbytes\" -> apply the Action defined (ACCEPT)\n\nThe value must be "
                      "in the format: VALUE/UNITS, for example:\n - 10/mbytes, 1/gbytes, etc\n"},
    [KS_FWF_COUNTER] = {"counter", {{"packets", false}, {"name", true}}, 2, ""},
    [KS_FWF_LIMIT] = {"limit", {{"over", true}, {"units", true}}, 2,
                      "\nApply limits on connections.\n\nFor example when:\n - \"limit over "
                      "10/mbytes/minute\" -> apply the Action defined (DROP, ACCEPT, etc)\n    "
                      "(When there're more than 10MB per minute, apply an Action)\n\n - "
                      "\"limit until 10/mbytes/hour\" -> apply the Action defined "
                      "(ACCEPT)\n\nThe value must be in the format: VALUE/UNITS/TIME, for "
                      "example:\n - 10/mbytes/minute, 1/gbytes/hour, etc\n"},
};

const char *ks_fwf_statm_tooltip(int statm)
{
    return statm >= 0 && statm < KS_FWF_NSTATM ? statm_conf[statm].tooltip : "";
}

static const char *const over_until[] = {"over", "until"};
static const char *const ct_states[] = {"new", "established", "related", "invalid"};
static const char *const quota_values[] = {"1/bytes", "1/kbytes", "1/mbytes", "1/gbytes"};
static const char *const limit_values[] = {"1/bytes/second", "1/kbytes/minute",
                                           "1/mbytes/hour", "1/gbytes/day"};

size_t ks_fwf_opts(int statm, const char *const **opts, bool *show_opts, bool *show_op)
{
    *opts = NULL;
    *show_opts = *show_op = false;
    switch (statm) {
    case KS_FWF_DPORT:
    case KS_FWF_SPORT:
        *show_op = *show_opts = true;
        *opts = ks_fw_port_protocols;
        return KS_FW_NPORT_PROTOCOLS;
    case KS_FWF_DEST_IP:
    case KS_FWF_SOURCE_IP:
        *show_op = *show_opts = true;
        *opts = ks_fw_families + 1; /* without "inet" */
        return KS_FW_NFAMILIES - 1;
    case KS_FWF_IIFNAME:
    case KS_FWF_OIFNAME:
        *show_op = true;
        return 0;
    case KS_FWF_META:
        *show_op = *show_opts = true;
        *opts = ks_fw_expr_meta + 1; /* without "set" */
        return KS_FW_NEXPR_META - 1;
    case KS_FWF_ICMP:
    case KS_FWF_ICMPV6:
    case KS_FWF_CT_STATE:
    case KS_FWF_CT_MARK:
        *show_op = true;
        return 0;
    case KS_FWF_LOG:
        *show_opts = true;
        *opts = ks_fw_log_levels;
        return KS_FW_NLOG_LEVELS;
    case KS_FWF_QUOTA:
    case KS_FWF_LIMIT:
        *show_opts = true;
        *opts = over_until;
        return 2;
    default:
        return 0;
    }
}

int ks_fwf_default_opts(int statm)
{
    /* nftables' default log level is warn */
    return statm == KS_FWF_LOG ? ks_fw_index_of(ks_fw_log_levels, KS_FW_NLOG_LEVELS, "warn") : 0;
}

static const char *opts_text(const struct ks_fwf_statement *st)
{
    const char *const *opts;
    bool so, sop;
    size_t n = ks_fwf_opts(st->what, &opts, &so, &sop);
    return st->opts >= 0 && (size_t)st->opts < n ? opts[st->opts] : "";
}

size_t ks_fwf_values(int statm, const struct ks_fw_services *services, const char **out,
                     size_t max)
{
    size_t n = 0;
#define PUT_LIST(l, cnt)                         \
    for (size_t i_ = 0; i_ < (cnt) && n < max; i_++) \
        out[n++] = (l)[i_];
    switch (statm) {
    case KS_FWF_DPORT:
    case KS_FWF_SPORT:
        if (services != NULL)
            PUT_LIST((const char *const *)services->names, services->n);
        break;
    case KS_FWF_CT_STATE:
        PUT_LIST(ct_states, 4);
        break;
    case KS_FWF_META:
        PUT_LIST(ks_fw_protocols, KS_FW_NPROTOCOLS);
        break;
    case KS_FWF_ICMP:
    case KS_FWF_ICMPV6:
        PUT_LIST(ks_fw_icmp_types, KS_FW_NICMP_TYPES);
        break;
    case KS_FWF_QUOTA:
        PUT_LIST(quota_values, 4);
        break;
    case KS_FWF_LIMIT:
        PUT_LIST(limit_values, 4);
        break;
    default:
        break;
    }
#undef PUT_LIST
    return n;
}

void ks_fwf_title(const struct ks_fwf_statement *st, char *buf, size_t len)
{
    buf[0] = '\0';
    int idx = st->what;
    if (idx < 0 || idx >= KS_FWF_NSTATM)
        return;
    const struct statm_conf *sc = &statm_conf[idx];
    const char *name = sc->name, *opts = opts_text(st);
    if (idx == KS_FWF_DEST_IP || idx == KS_FWF_SOURCE_IP || idx == KS_FWF_DPORT ||
        idx == KS_FWF_SPORT)
        name = opts;
    const char *op = st->op >= 0 && st->op < KS_FW_NOPERATORS ? ks_fw_operators[st->op] : "==";
    if (idx == KS_FWF_META) {
        snprintf(buf, len, "%s %s %s %s", name, opts, op, st->value);
    } else if (idx == KS_FWF_QUOTA || idx == KS_FWF_LIMIT) {
        snprintf(buf, len, "%s %s %s", name, opts, st->value);
    } else {
        char keys[128] = "";
        size_t off = 0;
        for (size_t k = 0; k < sc->nkeys && off < sizeof(keys); k++)
            off += (size_t)snprintf(keys + off, sizeof(keys) - off, " %s", sc->keys[k].key);
        snprintf(buf, len, "%s%s %s %s", name, keys, op, st->value);
    }
}

static const char *verdict_of(int idx)
{
    return idx + 1 >= 0 && idx + 1 < KS_FW_NVERDICTS ? ks_fw_verdicts[idx + 1] : "";
}

bool ks_fwf_has_verdict_parms(int verdict)
{
    const char *v = verdict_of(verdict);
    return strcmp(v, "queue") == 0 || strcmp(v, "redirect") == 0 || strcmp(v, "tproxy") == 0 ||
           strcmp(v, "dnat") == 0 || strcmp(v, "snat") == 0 || strcmp(v, "masquerade") == 0;
}

size_t ks_fwf_verdict_parm_items(int verdict, const char *const **data)
{
    static const char *const num[] = {"num"}, *const to[] = {"to"}, *const masq[] = {"", "to"};
    const char *v = verdict_of(verdict);
    if (strcmp(v, "queue") == 0) {
        *data = num;
        return 1;
    }
    if (strcmp(v, "redirect") == 0 || strcmp(v, "tproxy") == 0 || strcmp(v, "snat") == 0 ||
        strcmp(v, "dnat") == 0) {
        *data = to;
        return 1;
    }
    if (strcmp(v, "masquerade") == 0) {
        *data = masq;
        return 2;
    }
    *data = NULL;
    return 0;
}

int ks_fwf_verdict_direction(int verdict, int direction)
{
    const char *v = verdict_of(verdict);
    if ((strcmp(v, "redirect") == 0 || strcmp(v, "dnat") == 0) && direction != KS_FWF_OUT &&
        direction != KS_FWF_PREROUTING)
        return KS_FWF_OUT;
    if (strcmp(v, "snat") == 0 && direction != KS_FWF_POSTROUTING)
        return KS_FWF_POSTROUTING;
    return -1;
}

const char *ks_fwf_check_direction(int verdict, int *direction)
{
    static char msg[128];
    const char *v = verdict_of(verdict);
    char up[16];
    size_t i;
    for (i = 0; i + 1 < sizeof(up) && v[i]; i++)
        up[i] = (char)(v[i] >= 'a' && v[i] <= 'z' ? v[i] - 'a' + 'A' : v[i]);
    up[i] = '\0';
    if ((strcmp(v, "redirect") == 0 || strcmp(v, "tproxy") == 0 || strcmp(v, "dnat") == 0) &&
        (*direction == KS_FWF_IN || *direction == KS_FWF_POSTROUTING)) {
        snprintf(msg, sizeof(msg), "%s cannot be used with IN or POSTROUTING directions.", up);
        return msg;
    }
    if (strcmp(v, "snat") == 0 && *direction != KS_FWF_POSTROUTING) {
        snprintf(msg, sizeof(msg), "%s can only be used with POSTROUTING.", up);
        *direction = KS_FWF_POSTROUTING;
        return msg;
    }
    return NULL;
}

/* int(value) in Python: optional blanks and sign, decimal digits with
 * single underscores between them. */
static bool py_int(const char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\n')
        s++;
    if (*s == '+' || *s == '-')
        s++;
    if (*s < '0' || *s > '9')
        return false;
    bool under = false;
    for (; *s >= '0' || *s == '_'; s++) {
        if (*s == '_') {
            if (under)
                return false;
            under = true;
            continue;
        }
        if (*s > '9')
            break;
        under = false;
    }
    if (under)
        return false;
    while (*s == ' ' || *s == '\t' || *s == '\n')
        s++;
    return *s == '\0';
}

/* ipaddress.ip_address(): IPv4 (four decimal octets without leading
 * zeros) or IPv6. */
static bool py_ipv4(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (*s < '0' || *s > '9')
            return false;
        unsigned o = 0, digits = 0;
        const char *start = s;
        while (*s >= '0' && *s <= '9') {
            o = o * 10 + (unsigned)(*s++ - '0');
            if (++digits > 3)
                return false;
        }
        if (o > 255 || (digits > 1 && *start == '0'))
            return false;
        v = (v << 8) | o;
        if (i < 3 && *s++ != '.')
            return false;
    }
    if (*s != '\0')
        return false;
    if (out != NULL)
        *out = v;
    return true;
}

static bool py_ip(const char *s)
{
    unsigned char b[16];
    return py_ipv4(s, NULL) || (strchr(s, ':') != NULL && inet_pton(AF_INET6, s, b) == 1);
}

/* ip_network(value): first and last address ("a-b") */
static int py_network(const char *s, char *out, size_t len, char *err, size_t errlen)
{
    char addr[128];
    const char *slash = strchr(s, '/');
    snprintf(addr, sizeof(addr), "%.*s", (int)(slash - s), s);
    const char *pfx = slash + 1;
    char *end;
    long bits = strtol(pfx, &end, 10);
    uint32_t v4;
    unsigned char v6[16];
    if (py_ipv4(addr, &v4)) {
        if (*pfx == '\0' || *end != '\0' || bits < 0 || bits > 32)
            goto bad;
        uint32_t mask = bits == 0 ? 0 : 0xffffffffu << (32 - bits);
        if ((v4 & ~mask) != 0) {
            snprintf(err, errlen, "%.200s has host bits set", s);
            return -1;
        }
        uint32_t last = v4 | ~mask;
        snprintf(out, len, "%u.%u.%u.%u-%u.%u.%u.%u", v4 >> 24, (v4 >> 16) & 255,
                 (v4 >> 8) & 255, v4 & 255, last >> 24, (last >> 16) & 255, (last >> 8) & 255,
                 last & 255);
        return 0;
    }
    if (strchr(addr, ':') != NULL && inet_pton(AF_INET6, addr, v6) == 1) {
        if (*pfx == '\0' || *end != '\0' || bits < 0 || bits > 128)
            goto bad;
        unsigned char last[16];
        for (int i = 0; i < 16; i++) {
            int keep = (int)bits - i * 8;
            unsigned char m = keep >= 8 ? 0xff : keep <= 0 ? 0 : (unsigned char)(0xff << (8 - keep));
            if (v6[i] & ~m) {
                snprintf(err, errlen, "%.200s has host bits set", s);
                return -1;
            }
            last[i] = (unsigned char)(v6[i] | ~m);
        }
        char a[64], b[64];
        inet_ntop(AF_INET6, v6, a, sizeof(a));
        inet_ntop(AF_INET6, last, b, sizeof(b));
        snprintf(out, len, "%s-%s", a, b);
        return 0;
    }
bad:
    snprintf(err, errlen, "'%.200s' does not appear to be an IPv4 or IPv6 network", s);
    return -1;
}

static void remove_spaces(const char *s, char *out, size_t len)
{
    size_t o = 0;
    for (; *s && o + 1 < len; s++)
        if (*s != ' ')
            out[o++] = *s;
    out[o] = '\0';
}

static bool in_list(const char *const *l, size_t n, const char *v)
{
    return ks_fw_index_of(l, n, v) >= 0;
}

/* key_values of an expression being built */
struct kvs {
    char key[8][KS_FWF_VALUE_MAX];
    char value[8][KS_FWF_VALUE_MAX];
    size_t n;
};

static void kv_add(struct kvs *kv, const char *k, const char *v)
{
    for (size_t i = 0; i < kv->n; i++)
        if (strcmp(kv->key[i], k) == 0 && strcmp(kv->value[i], v) == 0)
            return; /* "statement values duplicated" */
    if (kv->n == 8)
        return;
    snprintf(kv->key[kv->n], KS_FWF_VALUE_MAX, "%s", k);
    snprintf(kv->value[kv->n], KS_FWF_VALUE_MAX, "%s", v);
    kv->n++;
}

static char *xstrdup(const char *s)
{
    return strdup(s != NULL ? s : "");
}

/* the chain a form's rule goes to */
static void form_chain(const struct ks_fwf_form *f, const char **name, const char **type,
                       const char **hook)
{
    int v = f->verdict + 1;
    bool natv = v == ks_fw_index_of(ks_fw_verdicts, KS_FW_NVERDICTS, "tproxy") ||
                v == ks_fw_index_of(ks_fw_verdicts, KS_FW_NVERDICTS, "dnat") ||
                v == ks_fw_index_of(ks_fw_verdicts, KS_FW_NVERDICTS, "redirect");
    *name = "filter_input";
    *type = "filter";
    *hook = "input";
    if (f->direction == KS_FWF_OUT && natv) {
        *name = "nat_output";
        *type = "natdest";
        *hook = "output";
    } else if (f->direction == KS_FWF_FORWARD) {
        *name = "mangle_forward";
        *type = "mangle";
        *hook = "forward";
    } else if (f->direction == KS_FWF_PREROUTING) {
        *name = "nat_prerouting";
        *type = "natdest";
        *hook = "prerouting";
    } else if (f->direction == KS_FWF_POSTROUTING) {
        *name = "nat_postrouting";
        *type = "natsource";
        *hook = "postrouting";
    } else if (f->direction == KS_FWF_OUT || f->form_type == KS_FWF_EXCLUDE_SERVICE) {
        *name = "mangle_output";
        *type = "mangle";
        *hook = "output";
    }
}

static int add_expression(struct ks_fw_rule *r, const char *op, const char *name,
                          const struct kvs *kv)
{
    struct ks_fw_expression *e =
        realloc(r->expressions.items, (r->expressions.len + 1) * sizeof(*e));
    if (e == NULL)
        return -1;
    r->expressions.items = e;
    r->expressions.non_nil = true;
    struct ks_fw_expression *x = &e[r->expressions.len++];
    x->statement = calloc(1, sizeof(*x->statement));
    if (x->statement == NULL)
        return -1;
    struct ks_fw_statement *st = x->statement;
    st->op = xstrdup(op);
    st->name = xstrdup(name);
    st->values.non_nil = true;
    if (kv->n > 0) {
        st->values.items = calloc(kv->n, sizeof(struct ks_fw_expr_value));
        if (st->values.items == NULL)
            return -1;
        st->values.len = kv->n;
        for (size_t i = 0; i < kv->n; i++) {
            KS_SYSFW_VALUE(st, i)->key = xstrdup(kv->key[i]);
            KS_SYSFW_VALUE(st, i)->value = xstrdup(kv->value[i]);
        }
    }
    return st->op && st->name ? 0 : -1;
}

#define FAIL(...)                              \
    do {                                       \
        snprintf(err, errlen, __VA_ARGS__);    \
        goto fail;                             \
    } while (0)

int ks_fwf_to_rule(const struct ks_fwf_form *f, const struct ks_fw_services *services,
                   struct ks_fw_chain *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    const char *cname, *ctype, *chook;
    form_chain(f, &cname, &ctype, &chook);
    out->name = xstrdup(cname);
    out->table = xstrdup("opensnitch");
    out->family = xstrdup("inet");
    out->type = xstrdup(ctype);
    out->hook = xstrdup(chook);
    out->priority = xstrdup("");
    out->policy = xstrdup("");
    out->description = xstrdup("");

    const char *verdict = verdict_of(f->verdict);
    char tparms[KS_FWF_VALUE_MAX + 8] = "";
    if (ks_fwf_has_verdict_parms(f->verdict)) {
        if (f->verdict_parms[0] == '\0')
            FAIL("Verdict (%s) parameters cannot be empty.", verdict);
        if ((strcmp(verdict, "redirect") == 0 || strcmp(verdict, "tproxy") == 0 ||
             strcmp(verdict, "snat") == 0 || strcmp(verdict, "dnat") == 0) &&
            strchr(f->verdict_parms, ':') == NULL)
            FAIL("Verdict (%s) parameters format is: <IP>:port.", verdict);
        if (strcmp(verdict, "queue") == 0 && !py_int(f->verdict_parms))
            FAIL("Verdict (%s) parameters format must be a number", verdict);
        const char *const *items;
        size_t n = ks_fwf_verdict_parm_items(f->verdict, &items);
        const char *data = f->verdict_parm >= 0 && (size_t)f->verdict_parm < n
                               ? items[f->verdict_parm]
                               : "None";
        char p[KS_FWF_VALUE_MAX];
        remove_spaces(f->verdict_parms, p, sizeof(p));
        snprintf(tparms, sizeof(tparms), "%s %s", data, p);
    }

    /* Rules.new */
    struct ks_fw_rule *r = calloc(1, sizeof(*r));
    if (r == NULL)
        FAIL("out of memory");
    out->rules.items = r;
    out->rules.len = 1;
    out->rules.non_nil = true;
    char uuid[KS_UUID_STRLEN];
    if (f->uuid[0] == '\0')
        ks_fw_new_uuid1(uuid, sizeof(uuid));
    r->uuid = xstrdup(f->uuid[0] != '\0' ? f->uuid : uuid);
    r->enabled = f->enabled;
    r->description = xstrdup(f->description);
    r->target = xstrdup(verdict);
    r->target_parameters = xstrdup(tparms);
    r->table = xstrdup("");
    r->chain = xstrdup("");
    r->parameters = xstrdup("");
    r->expressions.non_nil = true;

    for (size_t k = 0; k < f->nst; k++) {
        const struct ks_fwf_statement *st = &f->st[k];
        int idx = st->what;
        if (idx < 0 || idx >= KS_FWF_NSTATM)
            FAIL("select a statement.");
        const struct statm_conf *sc = &statm_conf[idx];
        const char *statement = sc->name;
        const char *op = st->op >= 0 && st->op < KS_FW_NOPERATORS ? ks_fw_operators[st->op] : "==";
        char sopts[64];
        snprintf(sopts, sizeof(sopts), "%s", opts_text(st));
        for (char *c = sopts; *c; c++)
            if (*c >= 'A' && *c <= 'Z')
                *c = (char)(*c - 'A' + 'a');
        struct kvs kv;
        kv.n = 0;
        for (size_t ki = 0; ki < sc->nkeys; ki++) {
            const char *key = sc->keys[ki].key;
            if (!sc->keys[ki].has_values) {
                kv_add(&kv, key, "");
                continue;
            }
            char value[KS_FWF_VALUE_MAX];
            snprintf(value, sizeof(value), "%s", st->value);
            if (value[0] == '\0' || (strcmp(value, "0") == 0 && idx != KS_FWF_META))
                FAIL("value cannot be 0 or empty.");

            if (idx == KS_FWF_QUOTA) {
                if (strcmp(key, "over") == 0) {
                    if (st->opts == 0)
                        kv_add(&kv, key, "");
                    continue;
                }
                char *slash = strchr(value, '/');
                if (slash == NULL || strchr(slash + 1, '/') != NULL ||
                    !in_list(ks_fw_rate_units, KS_FW_NRATE_UNITS, slash + 1))
                    FAIL("the value format is 1024/kbytes (or bytes, mbytes, gbytes)");
                *slash = '\0';
                if (!py_int(value))
                    FAIL("quota value is invalid (%s). It must be value/unit (1/kbytes)", value);
                char v[KS_FWF_VALUE_MAX];
                remove_spaces(value, v, sizeof(v));
                kv_add(&kv, slash + 1, v);
                continue;
            }
            if (idx == KS_FWF_LIMIT) {
                if (strcmp(key, "over") == 0) {
                    if (st->opts == 0)
                        kv_add(&kv, key, "");
                } else {
                    char *a = strchr(value, '/'), *b = a ? strchr(a + 1, '/') : NULL;
                    if (a == NULL || b == NULL || strchr(b + 1, '/') != NULL)
                        FAIL("the value format is 1024/kbytes/second (or bytes, mbytes, "
                             "gbytes)");
                    *a = *b = '\0';
                    if (!in_list(ks_fw_rate_units, KS_FW_NRATE_UNITS, a + 1))
                        FAIL("rate-limit not valid, use: bytes, kbytes, mbytes or gbytes.");
                    if (!in_list(ks_fw_time_units, KS_FW_NTIME_UNITS, b + 1))
                        FAIL("time-limit not valid, use: second, minute, hour or day");
                    kv_add(&kv, "units", value);
                    kv_add(&kv, "rate-units", a + 1);
                    kv_add(&kv, "time-units", b + 1);
                }
                continue;
            }
            if (idx == KS_FWF_LOG) {
                kv_add(&kv, "level", sopts);
            } else if (idx == KS_FWF_META) {
                key = opts_text(st);
            } else if (idx == KS_FWF_IIFNAME || idx == KS_FWF_OIFNAME) {
                /* the interface goes in the Key, the Value is empty */
                char v[KS_FWF_VALUE_MAX];
                remove_spaces(value, v, sizeof(v));
                kv_add(&kv, v, "");
                continue;
            } else if (idx == KS_FWF_DEST_IP || idx == KS_FWF_SOURCE_IP) {
                statement = st->opts == 1 ? "ip6" : "ip";
                if (strchr(value, '/') != NULL) {
                    char range[256], e[256];
                    if (py_network(value, range, sizeof(range), e, sizeof(e)) < 0)
                        FAIL("IP network format error, %s", e);
                    snprintf(value, sizeof(value), "%s", range);
                } else if (strchr(value, '-') == NULL && !py_ip(value)) {
                    FAIL("'%s' does not appear to be an IPv4 or IPv6 address", value);
                }
            } else if (idx == KS_FWF_DPORT || idx == KS_FWF_SPORT) {
                if (st->opts == 0) { /* tcp,udp: meta l4proto */
                    statement = "meta";
                    kv_add(&kv, "l4proto", sopts);
                } else {
                    statement = st->opts > 0 && st->opts < KS_FW_NPORT_PROTOCOLS
                                    ? ks_fw_port_protocols[st->opts]
                                    : "tcp";
                }
                int si = ks_fw_services_by_name(services, value);
                if (si >= 0) {
                    snprintf(value, sizeof(value), "%s", services->ports[si]);
                } else if (strchr(value, ',') == NULL && strchr(value, '-') == NULL &&
                           !py_int(value)) {
                    FAIL("port not valid.");
                }
            } else if (idx == KS_FWF_CT_SET || idx == KS_FWF_CT_MARK ||
                       idx == KS_FWF_META_SET_MARK) {
                if (!py_int(value))
                    FAIL("Invalid value %s, number expected.", value);
            } else if (idx == KS_FWF_ICMP || idx == KS_FWF_ICMPV6) {
                char tmp[KS_FWF_VALUE_MAX * 2 + 2];
                snprintf(tmp, sizeof(tmp), "%s", value);
                for (char *t = tmp, *save = NULL;; t = NULL) {
                    char *tok = strtok_r(t, ",", &save);
                    if (tok == NULL)
                        break;
                    if (!in_list(ks_fw_icmp_types, KS_FW_NICMP_TYPES, tok))
                        FAIL("Invalid ICMP type \"%s\".", tok);
                }
                if (value[strlen(value) - 1] == ',' || value[0] == ',' || strstr(value, ",,"))
                    FAIL("Invalid ICMP type \"\".");
            }
            char v[KS_FWF_VALUE_MAX];
            remove_spaces(value, v, sizeof(v));
            kv_add(&kv, key, v);
        }
        if (add_expression(r, op, statement, &kv) < 0)
            FAIL("out of memory");
    }
    return 0;
fail:
    ks_fwr_free_chain(out);
    return -1;
}

/* ---- load() --------------------------------------------------------------- */

static void set_value(struct ks_fwf_statement *st, const char *v)
{
    size_t n = strlen(v);
    if (n >= sizeof(st->value))
        n = sizeof(st->value) - 1;
    memcpy(st->value, v, n);
    st->value[n] = '\0';
}

/* a value appended with "," unless it's already in the text */
static void join_values(struct ks_fwf_statement *st, const struct ks_fw_statement *s)
{
    set_value(st, KS_SYSFW_VALUE(s, 0)->value);
    for (size_t i = 0; i < s->values.len; i++) {
        const char *v = KS_SYSFW_VALUE(s, i)->value;
        if (strstr(st->value, v) == NULL) {
            char tmp[KS_FWF_VALUE_MAX * 2 + 2];
            snprintf(tmp, sizeof(tmp), "%s,%s", st->value, v);
            set_value(st, tmp);
        }
    }
}

static void port_value(struct ks_fwf_statement *st, const char *port,
                       const struct ks_fw_services *services)
{
    int pidx = ks_fw_services_by_port(services, port);
    set_value(st, pidx >= 0 ? services->names[pidx] : port);
}

static void select_what(struct ks_fwf_statement *st, int what)
{
    st->what = what;
    st->opts = ks_fwf_default_opts(what);
}

int ks_fwf_from_rule(const struct ks_fw_chain *flat, const struct ks_fw_services *services,
                     struct ks_fwf_form *f, char *err, size_t errlen)
{
    memset(f, 0, sizeof(*f));
    f->form_type = KS_FWF_SIMPLE;
    f->verdict = 0;
    static const char *const hooks[] = {"input", "output", "forward", "prerouting",
                                        "postrouting"};
    static const int dirs[] = {KS_FWF_IN, KS_FWF_OUT, KS_FWF_FORWARD, KS_FWF_PREROUTING,
                               KS_FWF_POSTROUTING};
    int hi = -1;
    for (int i = 0; i < 5; i++)
        if (ieq(flat->hook, hooks[i]))
            hi = i;
    if (flat->rules.len == 0 || hi < 0) {
        snprintf(err, errlen, "Rule hook (%s) not supported yet",
                 flat->rules.len == 0 ? "invalid" : nz(flat->hook));
        return -1;
    }
    const struct ks_fw_rule *r = KS_SYSFW_RULE(flat, 0);
    f->enabled = r->enabled;
    snprintf(f->description, sizeof(f->description), "%s", nz(r->description));
    snprintf(f->uuid, sizeof(f->uuid), "%s", nz(r->uuid));
    f->nst = r->expressions.len <= 1 ? 1 : r->expressions.len;
    if (f->nst > KS_FWF_MAX_STATEMENTS)
        f->nst = KS_FWF_MAX_STATEMENTS;
    for (size_t i = 0; i < f->nst; i++)
        f->st[i].what = -1;

    for (size_t i = 0; i < r->expressions.len && i < f->nst; i++) {
        const struct ks_fw_statement *s = KS_SYSFW_EXPR(r, i)->statement;
        struct ks_fwf_statement *st = &f->st[i];
        if (s == NULL)
            goto unsupported;
        const char *name = nz(s->name);
        const struct ks_fw_expr_value *v0 = s->values.len > 0 ? KS_SYSFW_VALUE(s, 0) : NULL;
        bool port = strcmp(name, "tcp") == 0 || strcmp(name, "udp") == 0 ||
                    strcmp(name, "udplite") == 0 || strcmp(name, "sctp") == 0 ||
                    strcmp(name, "dccp") == 0;
        if (port || strcmp(name, "ip") == 0 || strcmp(name, "ip6") == 0 ||
            strcmp(name, "iifname") == 0 || strcmp(name, "oifname") == 0 ||
            strcmp(name, "icmp") == 0 || strcmp(name, "icmpv6") == 0 ||
            strcmp(name, "ct") == 0) {
            if (v0 == NULL)
                goto unsupported;
        }
        if (port) {
            if (strcmp(v0->key, "dport") == 0)
                select_what(st, KS_FWF_DPORT);
            else if (strcmp(v0->key, "sport") == 0)
                select_what(st, KS_FWF_SPORT);
            port_value(st, v0->value, services);
            st->opts = ks_fw_index_of(ks_fw_port_protocols, KS_FW_NPORT_PROTOCOLS, name);
        } else if (strcmp(name, "ip") == 0 || strcmp(name, "ip6") == 0) {
            if (strcmp(v0->key, "daddr") == 0)
                select_what(st, KS_FWF_DEST_IP);
            else if (strcmp(v0->key, "saddr") == 0)
                select_what(st, KS_FWF_SOURCE_IP);
            set_value(st, v0->value);
            st->opts = strcmp(name, "ip6") == 0 ? 1 : 0;
        } else if (strcmp(name, "iifname") == 0 || strcmp(name, "oifname") == 0) {
            select_what(st, name[0] == 'i' ? KS_FWF_IIFNAME : KS_FWF_OIFNAME);
            set_value(st, v0->key);
        } else if (strcmp(name, "ct") == 0) {
            if (strcmp(v0->key, "state") == 0) {
                select_what(st, KS_FWF_CT_STATE);
                join_values(st, s);
            } else if (strcmp(v0->key, "set") == 0) {
                select_what(st, KS_FWF_CT_SET);
                for (size_t j = 0; j < s->values.len; j++) {
                    if (strcmp(KS_SYSFW_VALUE(s, j)->key, "mark") == 0) {
                        set_value(st, KS_SYSFW_VALUE(s, j)->value);
                        break;
                    }
                }
            } else if (strcmp(v0->key, "mark") == 0) {
                select_what(st, KS_FWF_CT_MARK);
                set_value(st, v0->value);
            }
        } else if (strcmp(name, "meta") == 0) {
            /* _load_meta_statement */
            bool set_mark = false, multi = false;
            int statm = KS_FWF_SPORT;
            const char *value = "", *opts = "";
            for (size_t j = 0; j < s->values.len; j++) {
                const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(s, j);
                if (strcmp(v->key, "set") == 0) {
                    set_mark = true;
                    continue;
                }
                if (set_mark && strcmp(v->key, "mark") == 0) {
                    statm = KS_FWF_META_SET_MARK;
                    if (py_int(v->value))
                        value = v->value;
                    break;
                }
                if (strcmp(v->key, "l4proto") == 0)
                    opts = v->value;
                if (strcmp(v->key, "sport") == 0 || strcmp(v->key, "dport") == 0) {
                    statm = v->key[0] == 'd' ? KS_FWF_DPORT : KS_FWF_SPORT;
                    multi = true;
                    value = v->value;
                    break;
                }
            }
            if (set_mark) {
                select_what(st, statm);
                set_value(st, value);
            } else if (multi) {
                select_what(st, statm);
                int o = ks_fw_index_of(ks_fw_port_protocols, KS_FW_NPORT_PROTOCOLS, opts);
                st->opts = o >= 0 ? o : 0;
                port_value(st, value, services);
            } else if (v0 != NULL) {
                select_what(st, KS_FWF_META);
                int o = ks_fw_index_of(ks_fw_expr_meta, KS_FW_NEXPR_META, v0->key) - 1;
                st->opts = o >= 0 ? o : 0;
                set_value(st, v0->value);
            } else {
                select_what(st, KS_FWF_META);
            }
        } else if (strcmp(name, "icmp") == 0 || strcmp(name, "icmpv6") == 0) {
            select_what(st, name[4] == '\0' ? KS_FWF_ICMP : KS_FWF_ICMPV6);
            join_values(st, s);
        } else if (strcmp(name, "log") == 0) {
            select_what(st, KS_FWF_LOG);
            for (size_t j = 0; j < s->values.len; j++) {
                const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(s, j);
                if (strcmp(v->key, "prefix") == 0) {
                    set_value(st, v->value);
                } else if (strcmp(v->key, "level") == 0) {
                    int l = ks_fw_index_of(ks_fw_log_levels, KS_FW_NLOG_LEVELS, v->value);
                    st->opts = l >= 0 ? l : ks_fwf_default_opts(KS_FWF_LOG);
                }
            }
        } else if (strcmp(name, "quota") == 0) {
            select_what(st, KS_FWF_QUOTA);
            st->opts = 1;
            for (size_t j = 0; j < s->values.len; j++) {
                const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(s, j);
                if (strcmp(v->key, "over") == 0) {
                    st->opts = 0;
                } else {
                    char tmp[KS_FWF_VALUE_MAX * 2 + 2];
                    snprintf(tmp, sizeof(tmp), "%s/%s", v->value, v->key);
                    set_value(st, tmp);
                }
            }
        } else if (strcmp(name, "limit") == 0) {
            select_what(st, KS_FWF_LIMIT);
            st->opts = 1;
            char lval[KS_FWF_VALUE_MAX] = "";
            for (size_t j = 0; j < s->values.len; j++) {
                const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(s, j);
                char tmp[KS_FWF_VALUE_MAX * 2 + 2];
                if (strcmp(v->key, "over") == 0) {
                    st->opts = 0;
                } else if (strcmp(v->key, "units") == 0) {
                    snprintf(lval, sizeof(lval), "%s", v->value);
                } else if (strcmp(v->key, "rate-units") == 0 ||
                           strcmp(v->key, "time-units") == 0) {
                    snprintf(tmp, sizeof(tmp), "%s/%s", lval, v->value);
                    tmp[sizeof(lval) - 1] = '\0';
                    memcpy(lval, tmp, strlen(tmp) + 1);
                }
            }
            set_value(st, lval);
        } else if (strcmp(name, "counter") == 0) {
            select_what(st, KS_FWF_COUNTER);
            for (size_t j = 0; j < s->values.len; j++)
                if (strcmp(KS_SYSFW_VALUE(s, j)->key, "name") == 0)
                    set_value(st, KS_SYSFW_VALUE(s, j)->value);
        } else {
            goto unsupported;
        }
        /* no operator is "==" */
        const char *op = nz(s->op)[0] == '\0' ? "==" : s->op;
        st->op = ks_fw_index_of(ks_fw_operators, KS_FW_NOPERATORS, op);
        if (st->op < 0)
            goto unsupported;
    }
    f->direction = dirs[hi];

    char target[64];
    snprintf(target, sizeof(target), "%s", nz(r->target));
    for (char *c = target; *c; c++)
        if (*c >= 'A' && *c <= 'Z')
            *c = (char)(*c - 'A' + 'a');
    int vi = ks_fw_index_of(ks_fw_verdicts, KS_FW_NVERDICTS, target);
    if (vi < 0 || vi - 1 >= KS_FWF_NVERDICT_ITEMS) {
        snprintf(err, errlen, "Rule target (%s) not supported yet", target);
        return -1;
    }
    f->verdict = vi - 1;
    if (ks_fwf_has_verdict_parms(f->verdict)) {
        const char *sp = strchr(nz(r->target_parameters), ' ');
        if (sp == NULL) {
            snprintf(err, errlen, "Rule target (%s) not supported yet", target);
            return -1;
        }
        char p[KS_FWF_VALUE_MAX];
        snprintf(p, sizeof(p), "%s", sp + 1);
        char *sp2 = strchr(p, ' ');
        if (sp2 != NULL)
            *sp2 = '\0';
        for (char *c = p; *c; c++)
            if (*c >= 'A' && *c <= 'Z')
                *c = (char)(*c - 'A' + 'a');
        snprintf(f->verdict_parms, sizeof(f->verdict_parms), "%s", p);
    }
    return 0;
unsupported:
    snprintf(err, errlen, "This rule is not supported yet.");
    return -1;
}
