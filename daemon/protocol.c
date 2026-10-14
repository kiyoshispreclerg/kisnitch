/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream Rule.Serialize()/Deserialize() (daemon/rule/rule.go),
 * Connection.Serialize() (daemon/conman/connection.go) and NewAlert()
 * (daemon/ui/alerts.go).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/log.h"
#include "common/netaddr.h"
#include "common/unicode.h"
#include "daemon/procmon/process.h"
#include "daemon/rules/rule.h"

/* protobuf-c wants char *; packing never writes through it. */
static char *S(const char *s)
{
    return (char *)(uintptr_t)(s != NULL ? s : "");
}

uint64_t ks_unix_nano(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

/* ---- time.Parse(time.RFC3339) ---------------------------------------------- */

static int digits(const char *s, int n)
{
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

/* Days from 1970-01-01 to y-m-d (proleptic Gregorian). */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

int ks_parse_rfc3339(const char *s, int64_t *unix_out)
{
    static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    size_t n = strlen(s);
    if (n < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':')
        return -1;
    int y = digits(s, 4), mo = digits(s + 5, 2), d = digits(s + 8, 2);
    int h = digits(s + 11, 2), mi = digits(s + 14, 2), se = digits(s + 17, 2);
    if (y < 0 || mo < 1 || mo > 12 || d < 1 || h < 0 || h > 23 || mi < 0 || mi > 59 ||
        se < 0 || se > 59)
        return -1;
    bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (d > mdays[mo - 1] + (mo == 2 && leap))
        return -1;
    const char *p = s + 19;
    if (*p == '.' || *p == ',') { /* fractional seconds */
        p++;
        if (*p < '0' || *p > '9')
            return -1;
        while (*p >= '0' && *p <= '9')
            p++;
    }
    int64_t off = 0;
    if (p[0] == 'Z' && p[1] == '\0') {
        off = 0;
    } else if ((p[0] == '+' || p[0] == '-') && strlen(p) == 6 && p[3] == ':') {
        int oh = digits(p + 1, 2), om = digits(p + 4, 2);
        if (oh < 0 || om < 0 || oh > 23 || om > 59)
            return -1;
        off = (int64_t)(oh * 3600 + om * 60) * (p[0] == '-' ? -1 : 1);
    } else {
        return -1;
    }
    *unix_out = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - off;
    return 0;
}

/* ---- rules ----------------------------------------------------------------- */

static Protocol__Operator *pb_operator(struct ks_arena *a, const struct ks_operator *o,
                                       bool with_data)
{
    Protocol__Operator *po = ks_arena_alloc(a, sizeof(*po));
    if (po == NULL)
        return NULL;
    protocol__operator__init(po);
    po->type = S(o->type);
    po->sensitive = o->sensitive;
    po->operand = S(o->operand);
    po->data = with_data ? S(o->data) : S("");
    return po;
}

Protocol__Rule *ks_pb_rule(struct ks_arena *a, const struct ks_rule *r)
{
    if (r == NULL)
        return NULL;
    Protocol__Rule *pr = ks_arena_alloc(a, sizeof(*pr));
    if (pr == NULL)
        return NULL;
    protocol__rule__init(pr);

    int64_t created;
    if (r->created == NULL || ks_parse_rfc3339(r->created, &created) < 0) {
        ks_warning("Error parsing rule Created date (it should be in RFC3339 format): "
                   "%s  (%s)", r->created ? r->created : "", r->name ? r->name : "");
        created = (int64_t)time(NULL);
        ks_warning("using current time instead: %lld", (long long)created);
    }
    pr->created = created;
    pr->name = S(r->name);
    pr->description = S(r->description);
    pr->enabled = r->enabled;
    pr->precedence = r->precedence;
    pr->nolog = r->nolog;
    pr->action = S(r->action);
    pr->duration = S(r->duration);

    const struct ks_operator *o = &r->operator;
    bool is_list = o->type != NULL && strcmp(o->type, KS_TYPE_LIST) == 0;
    /* For lists upstream also blanks Data in the loaded rule itself; it
     * goes out empty either way (docs/UPSTREAM.md). */
    pr->operator_ = pb_operator(a, o, !is_list);
    if (pr->operator_ == NULL)
        return NULL;
    if (is_list && o->list.len > 0) {
        Protocol__Operator **items = ks_arena_calloc(a, o->list.len, sizeof(*items));
        if (items == NULL)
            return NULL;
        for (size_t i = 0; i < o->list.len; i++) {
            items[i] = pb_operator(a, KS_ARRAY_ITEM(o->list, struct ks_operator, i), true);
            if (items[i] == NULL)
                return NULL;
        }
        pr->operator_->list = items;
        pr->operator_->n_list = o->list.len;
    }
    return pr;
}

struct ks_rule *ks_rule_from_pb(const Protocol__Rule *pr, char *err, size_t errlen)
{
    if (pr->operator_ == NULL) {
        ks_warning("Deserialize rule, Operator nil");
        snprintf(err, errlen, "invalid operator");
        return NULL;
    }
    const Protocol__Operator *po = pr->operator_;
    bool is_list = strcmp(po->type, KS_TYPE_LIST) == 0;

    struct ks_operator op;
    memset(&op, 0, sizeof(op));
    op.type = S(po->type);
    op.sensitive = po->sensitive;
    op.operand = S(po->operand);
    op.data = is_list ? S("") : S(po->data);

    struct ks_operator *items = NULL;
    if (is_list && po->n_list > 0) {
        items = calloc(po->n_list, sizeof(*items));
        if (items == NULL) {
            snprintf(err, errlen, "out of memory");
            return NULL;
        }
        for (size_t i = 0; i < po->n_list; i++) {
            const Protocol__Operator *li = po->list[i];
            if (li == NULL)
                continue;
            items[i].type = S(li->type);
            items[i].sensitive = li->sensitive;
            items[i].operand = S(li->operand);
            items[i].data = S(li->data);
        }
        op.list.items = items;
        op.list.len = po->n_list;
        op.list.non_nil = true;
    }

    struct ks_rule *r = ks_rule_create(pr->name, pr->description, pr->enabled,
                                       pr->precedence, pr->nolog, pr->action,
                                       pr->duration, &op);
    free(items);
    if (r == NULL)
        snprintf(err, errlen, "out of memory");
    return r;
}

/* ---- connections ------------------------------------------------------------ */

Protocol__Connection *ks_pb_connection(struct ks_arena *a, const struct ks_conn *c,
                                       const struct ks_proc *p)
{
    Protocol__Connection *pc = ks_arena_alloc(a, sizeof(*pc));
    if (pc == NULL)
        return NULL;
    protocol__connection__init(pc);

    char ip[KS_IP_STRLEN];
    pc->protocol = S(c->protocol);
    ks_ip_string(&c->src_ip, ip, sizeof(ip));
    pc->src_ip = ks_arena_strdup(a, ip);
    pc->src_port = (uint32_t)c->src_port;
    ks_ip_string(&c->dst_ip, ip, sizeof(ip));
    pc->dst_ip = ks_arena_strdup(a, ip);
    pc->dst_host = S(c->dst_host);
    pc->dst_port = (uint32_t)c->dst_port;
    pc->user_id = (uint32_t)c->uid;
    if (pc->src_ip == NULL || pc->dst_ip == NULL)
        return NULL;
    if (p == NULL)
        return pc;

    pc->process_id = (uint32_t)p->pid;
    pc->process_path = S(p->path);
    pc->process_cwd = S(p->cwd);
    if (p->nargs > 0) {
        pc->process_args = ks_arena_calloc(a, p->nargs, sizeof(char *));
        if (pc->process_args == NULL)
            return NULL;
        for (size_t i = 0; i < p->nargs; i++)
            pc->process_args[i] = S(p->args[i]);
        pc->n_process_args = p->nargs;
    }
    if (p->nenv > 0) {
        Protocol__Connection__ProcessEnvEntry *e = ks_arena_calloc(a, p->nenv, sizeof(*e));
        pc->process_env = ks_arena_calloc(a, p->nenv, sizeof(*pc->process_env));
        if (e == NULL || pc->process_env == NULL)
            return NULL;
        for (size_t i = 0; i < p->nenv; i++) {
            protocol__connection__process_env_entry__init(&e[i]);
            e[i].key = S(p->env[i].name);
            e[i].value = S(p->env[i].value);
            pc->process_env[i] = &e[i];
        }
        pc->n_process_env = p->nenv;
    }
    const char *sums[2][2] = {{KS_HASH_MD5, p->checksum_md5},
                              {KS_HASH_SHA1, p->checksum_sha1}};
    size_t nsums = (p->checksum_md5 != NULL) + (p->checksum_sha1 != NULL);
    if (nsums > 0) {
        Protocol__Connection__ProcessChecksumsEntry *e = ks_arena_calloc(a, nsums,
                                                                         sizeof(*e));
        pc->process_checksums = ks_arena_calloc(a, nsums, sizeof(*pc->process_checksums));
        if (e == NULL || pc->process_checksums == NULL)
            return NULL;
        size_t k = 0;
        for (size_t i = 0; i < 2; i++) {
            if (sums[i][1] == NULL)
                continue;
            protocol__connection__process_checksums_entry__init(&e[k]);
            e[k].key = S(sums[i][0]);
            e[k].value = S(sums[i][1]);
            pc->process_checksums[k] = &e[k];
            k++;
        }
        pc->n_process_checksums = nsums;
    }
    if (p->ntree > 0) {
        Protocol__StringInt *t = ks_arena_calloc(a, p->ntree, sizeof(*t));
        pc->process_tree = ks_arena_calloc(a, p->ntree, sizeof(*pc->process_tree));
        if (t == NULL || pc->process_tree == NULL)
            return NULL;
        for (size_t i = 0; i < p->ntree; i++) {
            protocol__string_int__init(&t[i]);
            t[i].key = S(p->tree[i].path);
            t[i].value = (uint32_t)p->tree[i].pid;
            pc->process_tree[i] = &t[i];
        }
        pc->n_process_tree = p->ntree;
    }
    return pc;
}

/* ---- alerts ---------------------------------------------------------------- */

Protocol__Alert *ks_pb_alert_text(struct ks_arena *a, Protocol__Alert__Type type,
                                  Protocol__Alert__What what,
                                  Protocol__Alert__Action action,
                                  Protocol__Alert__Priority prio, const char *text)
{
    Protocol__Alert *al = ks_arena_alloc(a, sizeof(*al));
    if (al == NULL)
        return NULL;
    protocol__alert__init(al);
    al->id = ks_unix_nano();
    al->type = type;
    al->action = action;
    al->what = what;
    al->priority = prio;
    if (what == PROTOCOL__ALERT__WHAT__KERNEL_EVENT) {
        al->data_case = PROTOCOL__ALERT__DATA_TEXT;
        al->text = ks_arena_strdup(a, text);
        al->action = PROTOCOL__ALERT__ACTION__SHOW_ALERT;
    } else if (what == PROTOCOL__ALERT__WHAT__GENERIC) {
        al->data_case = PROTOCOL__ALERT__DATA_TEXT;
        al->text = ks_arena_strdup(a, text);
    }
    if (al->data_case == PROTOCOL__ALERT__DATA_TEXT && al->text == NULL)
        return NULL;
    return al;
}
