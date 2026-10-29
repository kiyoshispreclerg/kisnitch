/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/firewall/config/config.go (types) and the
 * Serialize() and Deserialize() of the firewalls.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "common/sysfw.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "common/json_util.h"

/* ---- schemas (field order is Go's struct order) --------------------- */

static const struct ks_schema_field value_fields[] = {
    KS_FIELD(struct ks_fw_expr_value, "Key", KS_T_STRING, key),
    KS_FIELD(struct ks_fw_expr_value, "Value", KS_T_STRING, value),
};
static const struct ks_schema value_schema =
    KS_SCHEMA("config.ExprValues", struct ks_fw_expr_value, value_fields);

static const struct ks_schema_field statement_fields[] = {
    KS_FIELD(struct ks_fw_statement, "Op", KS_T_STRING, op),
    KS_FIELD(struct ks_fw_statement, "Name", KS_T_STRING, name),
    KS_FIELD_SUB(struct ks_fw_statement, "Values", KS_T_ARRAY, values, value_schema),
};
static const struct ks_schema statement_schema =
    KS_SCHEMA("config.ExprStatement", struct ks_fw_statement, statement_fields);

static const struct ks_schema_field expression_fields[] = {
    KS_FIELD_SUB(struct ks_fw_expression, "Statement", KS_T_PTR, statement,
                 statement_schema),
};
static const struct ks_schema expression_schema =
    KS_SCHEMA("config.Expressions", struct ks_fw_expression, expression_fields);

static const struct ks_schema_field rule_fields[] = {
    KS_FIELD(struct ks_fw_rule, "Chain", KS_T_STRING, chain),
    KS_FIELD(struct ks_fw_rule, "Table", KS_T_STRING, table),
    KS_FIELD(struct ks_fw_rule, "Parameters", KS_T_STRING, parameters),
    KS_FIELD(struct ks_fw_rule, "UUID", KS_T_STRING, uuid),
    KS_FIELD(struct ks_fw_rule, "Description", KS_T_STRING, description),
    KS_FIELD(struct ks_fw_rule, "Target", KS_T_STRING, target),
    KS_FIELD(struct ks_fw_rule, "TargetParameters", KS_T_STRING, target_parameters),
    KS_FIELD_SUB(struct ks_fw_rule, "Expressions", KS_T_ARRAY, expressions,
                 expression_schema),
    KS_FIELD(struct ks_fw_rule, "Position", KS_T_UINT64_STR, position),
    KS_FIELD(struct ks_fw_rule, "Enabled", KS_T_BOOL, enabled),
};
const struct ks_schema ks_fw_rule_schema =
    KS_SCHEMA("config.FwRule", struct ks_fw_rule, rule_fields);

static const struct ks_schema_field chain_fields[] = {
    KS_FIELD(struct ks_fw_chain, "Table", KS_T_STRING, table),
    KS_FIELD(struct ks_fw_chain, "Family", KS_T_STRING, family),
    KS_FIELD(struct ks_fw_chain, "Name", KS_T_STRING, name),
    KS_FIELD(struct ks_fw_chain, "Description", KS_T_STRING, description),
    KS_FIELD(struct ks_fw_chain, "Priority", KS_T_STRING, priority),
    KS_FIELD(struct ks_fw_chain, "Type", KS_T_STRING, type),
    KS_FIELD(struct ks_fw_chain, "Hook", KS_T_STRING, hook),
    KS_FIELD(struct ks_fw_chain, "Policy", KS_T_STRING, policy),
    KS_FIELD_SUB(struct ks_fw_chain, "Rules", KS_T_ARRAY, rules, ks_fw_rule_schema),
};
const struct ks_schema ks_fw_chain_schema =
    KS_SCHEMA("config.FwChain", struct ks_fw_chain, chain_fields);

static const struct ks_schema_field chains_list_fields[] = {
    KS_FIELD_SUB(struct ks_fw_chains_list, "Rule", KS_T_PTR, rule, ks_fw_rule_schema),
    KS_FIELD_SUB(struct ks_fw_chains_list, "Chains", KS_T_ARRAY, chains, ks_fw_chain_schema),
};
static const struct ks_schema chains_list_schema =
    KS_SCHEMA("config.chainsList", struct ks_fw_chains_list, chains_list_fields);

static const struct ks_schema_field sysfw_fields[] = {
    KS_FIELD_SUB(struct ks_sysfw, "SystemRules", KS_T_ARRAY, system_rules,
                 chains_list_schema),
    KS_FIELD(struct ks_sysfw, "Version", KS_T_UINT32, version),
    KS_FIELD(struct ks_sysfw, "Enabled", KS_T_BOOL, enabled),
};
const struct ks_schema ks_sysfw_schema =
    KS_SCHEMA("config.SystemConfig", struct ks_sysfw, sysfw_fields);

int ks_sysfw_parse(const char *buf, size_t len, struct ks_sysfw *out, char *err,
                   size_t errlen)
{
    return ks_schema_decode_buf(&ks_sysfw_schema, buf, len, out, err, errlen);
}

void ks_sysfw_free(struct ks_sysfw *cfg)
{
    ks_schema_free(&ks_sysfw_schema, cfg);
}

int ks_sysfw_copy(struct ks_sysfw *dst, const struct ks_sysfw *src)
{
    return ks_schema_copy(&ks_sysfw_schema, dst, src);
}

bool ks_fw_chain_is_invalid(const struct ks_fw_chain *c)
{
    return c->name == NULL || c->name[0] == '\0' || c->family == NULL ||
           c->family[0] == '\0' || c->table == NULL || c->table[0] == '\0';
}

/* ---- Serialize ------------------------------------------------------- */

static char *pbstr(struct ks_arena *a, const char *s)
{
    return ks_arena_strdup(a, s != NULL ? s : "");
}

static Protocol__FwRule *rule_to_pb(struct ks_arena *a, const struct ks_fw_rule *r)
{
    Protocol__FwRule *p = ks_arena_alloc(a, sizeof(*p));
    if (p == NULL)
        return NULL;
    protocol__fw_rule__init(p);
    p->table = pbstr(a, r->table);
    p->chain = pbstr(a, r->chain);
    p->uuid = pbstr(a, r->uuid);
    p->enabled = r->enabled;
    p->position = r->position;
    p->description = pbstr(a, r->description);
    p->parameters = pbstr(a, r->parameters);
    p->target = pbstr(a, r->target);
    p->targetparameters = pbstr(a, r->target_parameters);
    size_t n = r->expressions.len;
    if (n > 0) {
        p->expressions = ks_arena_calloc(a, n, sizeof(*p->expressions));
        if (p->expressions == NULL)
            return NULL;
        p->n_expressions = n;
    }
    for (size_t i = 0; i < n; i++) {
        const struct ks_fw_expression *e = KS_SYSFW_EXPR(r, i);
        Protocol__Expressions *pe = ks_arena_alloc(a, sizeof(*pe));
        if (pe == NULL)
            return NULL;
        protocol__expressions__init(pe);
        p->expressions[i] = pe;
        if (e->statement == NULL)
            continue;
        const struct ks_fw_statement *st = e->statement;
        Protocol__Statement *ps = ks_arena_alloc(a, sizeof(*ps));
        if (ps == NULL)
            return NULL;
        protocol__statement__init(ps);
        pe->statement = ps;
        ps->op = pbstr(a, st->op);
        ps->name = pbstr(a, st->name);
        if (st->values.len > 0) {
            ps->values = ks_arena_calloc(a, st->values.len, sizeof(*ps->values));
            if (ps->values == NULL)
                return NULL;
            ps->n_values = st->values.len;
        }
        for (size_t j = 0; j < st->values.len; j++) {
            const struct ks_fw_expr_value *v = KS_SYSFW_VALUE(st, j);
            Protocol__StatementValues *pv = ks_arena_alloc(a, sizeof(*pv));
            if (pv == NULL)
                return NULL;
            protocol__statement_values__init(pv);
            pv->key = pbstr(a, v->key);
            pv->value = pbstr(a, v->value);
            ps->values[j] = pv;
        }
    }
    return a->failed ? NULL : p;
}

static Protocol__FwChain *chain_to_pb(struct ks_arena *a, const struct ks_fw_chain *c)
{
    Protocol__FwChain *p = ks_arena_alloc(a, sizeof(*p));
    if (p == NULL)
        return NULL;
    protocol__fw_chain__init(p);
    p->name = pbstr(a, c->name);
    p->table = pbstr(a, c->table);
    p->family = pbstr(a, c->family);
    p->priority = pbstr(a, c->priority);
    p->type = pbstr(a, c->type);
    p->hook = pbstr(a, c->hook);
    p->policy = pbstr(a, c->policy);
    if (c->rules.len > 0) {
        p->rules = ks_arena_calloc(a, c->rules.len, sizeof(*p->rules));
        if (p->rules == NULL)
            return NULL;
        p->n_rules = c->rules.len;
    }
    for (size_t i = 0; i < c->rules.len; i++)
        if ((p->rules[i] = rule_to_pb(a, KS_SYSFW_RULE(c, i))) == NULL)
            return NULL;
    return a->failed ? NULL : p;
}

Protocol__SysFirewall *ks_sysfw_to_pb(struct ks_arena *a, const struct ks_sysfw *cfg)
{
    Protocol__SysFirewall *p = ks_arena_alloc(a, sizeof(*p));
    if (p == NULL)
        return NULL;
    protocol__sys_firewall__init(p);
    p->enabled = cfg->enabled;
    p->version = cfg->version;
    size_t n = cfg->system_rules.len;
    if (n > 0) {
        p->systemrules = ks_arena_calloc(a, n, sizeof(*p->systemrules));
        if (p->systemrules == NULL)
            return NULL;
        p->n_systemrules = n;
    }
    for (size_t i = 0; i < n; i++) {
        const struct ks_fw_chains_list *l = KS_SYSFW_RULES(cfg, i);
        Protocol__FwChains *pl = ks_arena_alloc(a, sizeof(*pl));
        if (pl == NULL)
            return NULL;
        protocol__fw_chains__init(pl);
        p->systemrules[i] = pl;
        if (l->rule != NULL && (pl->rule = rule_to_pb(a, l->rule)) == NULL)
            return NULL;
        if (l->chains.len > 0) {
            pl->chains = ks_arena_calloc(a, l->chains.len, sizeof(*pl->chains));
            if (pl->chains == NULL)
                return NULL;
            pl->n_chains = l->chains.len;
        }
        for (size_t j = 0; j < l->chains.len; j++)
            if ((pl->chains[j] = chain_to_pb(a, KS_SYSFW_CHAIN(l, j))) == NULL)
                return NULL;
    }
    return a->failed ? NULL : p;
}

/* ---- Deserialize: golang/protobuf v1.5 jsonpb's jsonWriter ----------
 *
 * Generic over the protobuf-c descriptors, for the field types SysFirewall
 * uses (messages, strings, bools, uint32, uint64; singular and repeated). */

#define JSONPB_INDENT "  "

struct jbuf {
    char *p;
    size_t len, cap;
    bool oom;
};

static void jput(struct jbuf *b, const char *s)
{
    size_t n = strlen(s);
    if (b->oom)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 1024;
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

static void put_indent(struct jbuf *b, size_t depth)
{
    for (size_t i = 0; i < depth; i++)
        jput(b, JSONPB_INDENT);
}

static void marshal_message(struct jbuf *b, const ProtobufCMessage *m, size_t indent,
                            bool emit_defaults);

/* marshalSingularValue; `indent` is the depth of the field. */
static void marshal_singular(struct jbuf *b, const ProtobufCFieldDescriptor *fd,
                             const void *v, size_t indent, bool emit_defaults)
{
    char num[32];
    switch (fd->type) {
    case PROTOBUF_C_TYPE_MESSAGE: {
        const ProtobufCMessage *m = *(const ProtobufCMessage *const *)v;
        if (m == NULL)
            jput(b, "null");
        else
            marshal_message(b, m, indent + 1, emit_defaults);
        break;
    }
    case PROTOBUF_C_TYPE_STRING: {
        const char *s = *(const char *const *)v;
        char *q = ks_json_quote_go(s != NULL ? s : "");
        if (q == NULL) {
            b->oom = true;
            break;
        }
        jput(b, q);
        free(q);
        break;
    }
    case PROTOBUF_C_TYPE_BOOL:
        jput(b, *(const protobuf_c_boolean *)v ? "true" : "false");
        break;
    case PROTOBUF_C_TYPE_UINT32:
        snprintf(num, sizeof(num), "%u", *(const uint32_t *)v);
        jput(b, num);
        break;
    case PROTOBUF_C_TYPE_UINT64:
        /* int64 and uint64 are quoted */
        snprintf(num, sizeof(num), "\"%llu\"", (unsigned long long)*(const uint64_t *)v);
        jput(b, num);
        break;
    default:
        /* not used by SysFirewall */
        jput(b, "null");
        break;
    }
}

static size_t field_size(const ProtobufCFieldDescriptor *fd)
{
    switch (fd->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        return sizeof(void *);
    case PROTOBUF_C_TYPE_BOOL:
        return sizeof(protobuf_c_boolean);
    case PROTOBUF_C_TYPE_UINT32:
        return sizeof(uint32_t);
    case PROTOBUF_C_TYPE_UINT64:
        return sizeof(uint64_t);
    default:
        return 0;
    }
}

/* Has(fd) for a proto3 field. */
static bool field_has(const ProtobufCFieldDescriptor *fd, const char *base)
{
    const void *v = base + fd->offset;
    if (fd->label == PROTOBUF_C_LABEL_REPEATED)
        return *(const size_t *)(base + fd->quantifier_offset) > 0;
    switch (fd->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        return *(void *const *)v != NULL;
    case PROTOBUF_C_TYPE_STRING: {
        const char *s = *(const char *const *)v;
        return s != NULL && s[0] != '\0';
    }
    case PROTOBUF_C_TYPE_BOOL:
        return *(const protobuf_c_boolean *)v != 0;
    case PROTOBUF_C_TYPE_UINT32:
        return *(const uint32_t *)v != 0;
    case PROTOBUF_C_TYPE_UINT64:
        return *(const uint64_t *)v != 0;
    default:
        return false;
    }
}

/* marshalMessage; `indent` is the message's depth. */
static void marshal_message(struct jbuf *b, const ProtobufCMessage *m, size_t indent,
                            bool emit_defaults)
{
    const ProtobufCMessageDescriptor *md = m->descriptor;
    const char *base = (const char *)m;
    jput(b, "{\n");
    bool first = true;
    for (unsigned i = 0; i < md->n_fields; i++) {
        const ProtobufCFieldDescriptor *fd = &md->fields[i];
        if (!field_has(fd, base) && !emit_defaults)
            continue;
        if (!first)
            jput(b, ",\n");
        first = false;
        /* marshalField */
        put_indent(b, indent + 1);
        jput(b, "\"");
        jput(b, fd->name);
        jput(b, "\": ");
        if (fd->label == PROTOBUF_C_LABEL_REPEATED) {
            size_t n = *(const size_t *)(base + fd->quantifier_offset);
            const char *items = *(const char *const *)(base + fd->offset);
            size_t sz = field_size(fd);
            jput(b, "[");
            for (size_t j = 0; j < n; j++) {
                if (j > 0)
                    jput(b, ",");
                jput(b, "\n");
                put_indent(b, indent + 2);
                marshal_singular(b, fd, items + j * sz, indent + 1, emit_defaults);
            }
            jput(b, "\n");
            put_indent(b, indent + 1);
            jput(b, "]");
        } else {
            marshal_singular(b, fd, base + fd->offset, indent, emit_defaults);
        }
    }
    jput(b, "\n");
    put_indent(b, indent);
    jput(b, "}");
}

char *ks_sysfw_pb_to_json(const Protocol__SysFirewall *fw, bool emit_defaults)
{
    struct jbuf b = {0};
    marshal_message(&b, &fw->base, 0, emit_defaults);
    if (b.oom) {
        free(b.p);
        return NULL;
    }
    return b.p;
}

/* ---- uuid ------------------------------------------------------------ */

int ks_fw_new_uuid(char *buf, size_t len)
{
    uint8_t u[16];
    size_t got = 0;
    while (got < sizeof(u)) {
        ssize_t n = getrandom(u + got, sizeof(u) - got, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)n;
    }
    u[6] = (uint8_t)((u[6] & 0x0f) | 0x40); /* version 4 */
    u[8] = (uint8_t)((u[8] & 0x3f) | 0x80); /* RFC 4122 variant */
    snprintf(buf, len,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11],
             u[12], u[13], u[14], u[15]);
    return 0;
}


/* ---- protobuf -> struct ------------------------------------------------ */

static int dup_str(char **dst, const char *src)
{
    *dst = strdup(src != NULL ? src : "");
    return *dst != NULL ? 0 : -1;
}

static int array_alloc(struct ks_array *a, size_t n, size_t size)
{
    a->non_nil = true;
    a->len = 0;
    a->items = NULL;
    if (n == 0)
        return 0;
    a->items = calloc(n, size);
    if (a->items == NULL)
        return -1;
    a->len = n;
    return 0;
}

static int rule_from_pb(struct ks_fw_rule *r, const Protocol__FwRule *p)
{
    if (dup_str(&r->table, p->table) < 0 || dup_str(&r->chain, p->chain) < 0 ||
        dup_str(&r->uuid, p->uuid) < 0 || dup_str(&r->description, p->description) < 0 ||
        dup_str(&r->parameters, p->parameters) < 0 || dup_str(&r->target, p->target) < 0 ||
        dup_str(&r->target_parameters, p->targetparameters) < 0)
        return -1;
    r->enabled = p->enabled;
    r->position = p->position;
    if (array_alloc(&r->expressions, p->n_expressions, sizeof(struct ks_fw_expression)) < 0)
        return -1;
    for (size_t i = 0; i < p->n_expressions; i++) {
        const Protocol__Statement *ps = p->expressions[i]->statement;
        if (ps == NULL)
            continue;
        struct ks_fw_statement *st = calloc(1, sizeof(*st));
        if (st == NULL)
            return -1;
        KS_SYSFW_EXPR(r, i)->statement = st;
        if (dup_str(&st->op, ps->op) < 0 || dup_str(&st->name, ps->name) < 0 ||
            array_alloc(&st->values, ps->n_values, sizeof(struct ks_fw_expr_value)) < 0)
            return -1;
        for (size_t j = 0; j < ps->n_values; j++)
            if (dup_str(&KS_SYSFW_VALUE(st, j)->key, ps->values[j]->key) < 0 ||
                dup_str(&KS_SYSFW_VALUE(st, j)->value, ps->values[j]->value) < 0)
                return -1;
    }
    return 0;
}

static int chain_from_pb(struct ks_fw_chain *c, const Protocol__FwChain *p)
{
    if (dup_str(&c->name, p->name) < 0 || dup_str(&c->table, p->table) < 0 ||
        dup_str(&c->family, p->family) < 0 || dup_str(&c->priority, p->priority) < 0 ||
        dup_str(&c->type, p->type) < 0 || dup_str(&c->hook, p->hook) < 0 ||
        dup_str(&c->policy, p->policy) < 0 || dup_str(&c->description, "") < 0)
        return -1;
    if (array_alloc(&c->rules, p->n_rules, sizeof(struct ks_fw_rule)) < 0)
        return -1;
    for (size_t i = 0; i < p->n_rules; i++)
        if (rule_from_pb(KS_SYSFW_RULE(c, i), p->rules[i]) < 0)
            return -1;
    return 0;
}

int ks_sysfw_from_pb(struct ks_sysfw *out, const Protocol__SysFirewall *fw)
{
    memset(out, 0, sizeof(*out));
    out->enabled = fw->enabled;
    out->version = fw->version;
    if (array_alloc(&out->system_rules, fw->n_systemrules, sizeof(struct ks_fw_chains_list)) <
        0)
        goto oom;
    for (size_t i = 0; i < fw->n_systemrules; i++) {
        const Protocol__FwChains *pl = fw->systemrules[i];
        struct ks_fw_chains_list *l = KS_SYSFW_RULES(out, i);
        if (pl->rule != NULL) {
            if ((l->rule = calloc(1, sizeof(*l->rule))) == NULL ||
                rule_from_pb(l->rule, pl->rule) < 0)
                goto oom;
        }
        if (array_alloc(&l->chains, pl->n_chains, sizeof(struct ks_fw_chain)) < 0)
            goto oom;
        for (size_t j = 0; j < pl->n_chains; j++)
            if (chain_from_pb(KS_SYSFW_CHAIN(l, j), pl->chains[j]) < 0)
                goto oom;
    }
    return 0;
oom:
    ks_sysfw_free(out);
    return -1;
}

/* ---- uuid1 --------------------------------------------------------------- */

/* uuid.getnode(): the MAC address of the first interface (by name) that has
 * one, or a random one with the multicast bit set. */
static uint64_t uuid_node(void)
{
    static uint64_t node;
    if (node != 0)
        return node;
    char best[64] = "";
    DIR *d = opendir("/sys/class/net");
    struct dirent *de;
    while (d != NULL && (de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' || strcmp(de->d_name, "lo") == 0 ||
            strlen(de->d_name) >= sizeof(best))
            continue;
        char path[300];
        snprintf(path, sizeof(path), "/sys/class/net/%.64s/address", de->d_name);
        FILE *f = fopen(path, "r");
        if (f == NULL)
            continue;
        unsigned b[6];
        uint64_t v = 0;
        if (fscanf(f, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6)
            for (int k = 0; k < 6; k++)
                v = (v << 8) | (b[k] & 0xff);
        fclose(f);
        if (v != 0 && (best[0] == '\0' || strcmp(de->d_name, best) < 0)) {
            snprintf(best, sizeof(best), "%.63s", de->d_name);
            node = v;
        }
    }
    if (d != NULL)
        closedir(d);
    if (node == 0) {
        uint8_t r[6] = {0};
        if (getrandom(r, sizeof(r), 0) != (ssize_t)sizeof(r))
            r[5] = 1;
        for (int k = 0; k < 6; k++)
            node = (node << 8) | r[k];
        node |= 0x010000000000ULL;
    }
    return node;
}

int ks_fw_new_uuid1(char *buf, size_t len)
{
    static uint64_t last;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
        return -1;
    /* 100ns intervals since 1582-10-15 */
    uint64_t t = (uint64_t)ts.tv_sec * 10000000ULL + (uint64_t)ts.tv_nsec / 100 +
                 0x01b21dd213814000ULL;
    if (t <= last)
        t = last + 1;
    last = t;
    uint16_t seq;
    if (getrandom(&seq, sizeof(seq), 0) != (ssize_t)sizeof(seq))
        seq = (uint16_t)ts.tv_nsec;
    seq &= 0x3fff;
    snprintf(buf, len, "%08x-%04x-%04x-%02x%02x-%012llx", (unsigned)(t & 0xffffffffu),
             (unsigned)((t >> 32) & 0xffff), (unsigned)(((t >> 48) & 0x0fff) | 0x1000),
             (unsigned)(((seq >> 8) & 0x3f) | 0x80), (unsigned)(seq & 0xff),
             (unsigned long long)uuid_node());
    return 0;
}
