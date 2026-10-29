/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The simplified firewall panel's logic. See fwsimple.h.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/fwsimple.h"
#include "ui/i18n.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "common/json_util.h"

static const struct ks_fw_services no_services = {0};

/* truncating copy */
static void copy(char *dst, size_t len, const char *src)
{
    size_t n = src != NULL ? strlen(src) : 0;
    if (n >= len)
        n = len - 1;
    if (n > 0)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool seq(const char *a, const char *b)
{
    return strcmp(a != NULL ? a : "", b != NULL ? b : "") == 0;
}

void ks_fws_rule_init(struct ks_fws_rule *r)
{
    memset(r, 0, sizeof(*r));
    r->enabled = true;
    r->action = KS_FWS_ALLOW;
    r->direction = KS_FWS_IN;
    r->proto = KS_FWS_ANY_PROTO;
}

/* ---- simple rule <-> form ------------------------------------------------- */

static struct ks_fwf_statement *add_st(struct ks_fwf_form *f, int what)
{
    struct ks_fwf_statement *st = &f->st[f->nst++];
    memset(st, 0, sizeof(*st));
    st->what = what;
    st->opts = ks_fwf_default_opts(what);
    st->op = 0; /* == */
    return st;
}

static int l4proto_index(void)
{
    return ks_fw_index_of(ks_fw_expr_meta, KS_FW_NEXPR_META, "l4proto") - 1;
}

static bool is_ipv6(const char *a)
{
    return strchr(a, ':') != NULL;
}

static int to_form(const struct ks_fws_rule *r, struct ks_fwf_form *f, char *err, size_t errlen)
{
    memset(f, 0, sizeof(*f));
    f->form_type = KS_FWF_SIMPLE;
    f->direction = r->direction == KS_FWS_OUT ? KS_FWF_OUT : KS_FWF_IN;
    f->verdict = r->action; /* accept, drop, reject: the first three */
    f->enabled = r->enabled;
    copy(f->description, sizeof(f->description), r->description);
    copy(f->uuid, sizeof(f->uuid), r->uuid);
    if (r->src[0] && r->dst[0] && is_ipv6(r->src) != is_ipv6(r->dst)) {
        snprintf(err, errlen, _("The source and destination addresses must be both IPv4 or both "
                              "IPv6."));
        return -1;
    }
    if (r->port[0] != '\0') {
        if (r->proto < 0 || r->proto >= KS_FW_NPORT_PROTOCOLS) {
            snprintf(err, errlen, _("Select the protocol of the port."));
            return -1;
        }
        struct ks_fwf_statement *st = add_st(f, KS_FWF_DPORT);
        st->opts = r->proto;
        copy(st->value, sizeof(st->value), r->port);
    } else if (r->proto >= 0) {
        if (r->proto == 0) { /* "tcp,udp" without a port: any protocol */
            snprintf(err, errlen, _("TCP and UDP need a port; without a port, select one "
                                  "protocol or \"any\"."));
            return -1;
        }
        /* a protocol alone: meta l4proto */
        struct ks_fwf_statement *st = add_st(f, KS_FWF_META);
        st->opts = l4proto_index();
        copy(st->value, sizeof(st->value), ks_fw_port_protocols[r->proto]);
    }
    if (r->src[0] != '\0') {
        struct ks_fwf_statement *st = add_st(f, KS_FWF_SOURCE_IP);
        st->opts = is_ipv6(r->src) ? 1 : 0;
        copy(st->value, sizeof(st->value), r->src);
    }
    if (r->dst[0] != '\0') {
        struct ks_fwf_statement *st = add_st(f, KS_FWF_DEST_IP);
        st->opts = is_ipv6(r->dst) ? 1 : 0;
        copy(st->value, sizeof(st->value), r->dst);
    }
    if (r->iface[0] != '\0') {
        struct ks_fwf_statement *st =
            add_st(f, r->direction == KS_FWS_OUT ? KS_FWF_OIFNAME : KS_FWF_IIFNAME);
        copy(st->value, sizeof(st->value), r->iface);
    }
    return 0;
}

/* the inverse of to_form; false if the form has anything else */
static bool from_form(const struct ks_fwf_form *f, struct ks_fws_rule *r)
{
    ks_fws_rule_init(r);
    if ((f->direction != KS_FWF_IN && f->direction != KS_FWF_OUT) || f->verdict < 0 ||
        f->verdict > 2 || f->verdict_parms[0] != '\0')
        return false;
    r->direction = f->direction == KS_FWF_OUT ? KS_FWS_OUT : KS_FWS_IN;
    r->action = f->verdict;
    r->enabled = f->enabled;
    copy(r->description, sizeof(r->description), f->description);
    copy(r->uuid, sizeof(r->uuid), f->uuid);
    bool port = false, proto = false;
    for (size_t i = 0; i < f->nst; i++) {
        const struct ks_fwf_statement *st = &f->st[i];
        if (st->op != 0)
            return false;
        switch (st->what) {
        case KS_FWF_DPORT:
            if (port || proto)
                return false;
            port = true;
            r->proto = st->opts;
            copy(r->port, sizeof(r->port), st->value);
            break;
        case KS_FWF_META:
            if (port || proto || st->opts != l4proto_index())
                return false;
            proto = true;
            r->proto = ks_fw_index_of(ks_fw_port_protocols, KS_FW_NPORT_PROTOCOLS, st->value);
            if (r->proto <= 0)
                return false;
            break;
        case KS_FWF_SOURCE_IP:
            if (r->src[0])
                return false;
            copy(r->src, sizeof(r->src), st->value);
            break;
        case KS_FWF_DEST_IP:
            if (r->dst[0])
                return false;
            copy(r->dst, sizeof(r->dst), st->value);
            break;
        case KS_FWF_IIFNAME:
        case KS_FWF_OIFNAME:
            if (r->iface[0] || (st->what == KS_FWF_IIFNAME) != (r->direction == KS_FWS_IN))
                return false;
            copy(r->iface, sizeof(r->iface), st->value);
            break;
        default:
            return false;
        }
    }
    return true;
}

int ks_fws_to_flat(const struct ks_fws_rule *r, struct ks_fw_chain *out, char *err,
                   size_t errlen)
{
    memset(out, 0, sizeof(*out));
    if (r->action < KS_FWS_ALLOW || r->action > KS_FWS_REJECT) {
        snprintf(err, errlen, _("Invalid action."));
        return -1;
    }
    struct ks_fwf_form f;
    if (to_form(r, &f, err, errlen) < 0)
        return -1;
    return ks_fwf_to_rule(&f, &no_services, out, err, errlen);
}

/* The rule the simple one makes is the same rule, UUID and position aside. */
static bool same_flat(const struct ks_fw_chain *a, const struct ks_fw_chain *b)
{
    if (!seq(a->name, b->name) || !seq(a->hook, b->hook) || !seq(a->table, b->table) ||
        !seq(a->family, b->family) || !seq(a->type, b->type) || a->rules.len != 1 ||
        b->rules.len != 1)
        return false;
    struct ks_fw_rule *ra = KS_SYSFW_RULE(a, 0);
    const struct ks_fw_rule *rb = KS_SYSFW_RULE(b, 0);
    /* the fields the form doesn't make */
    char *saved[4] = {ra->uuid, ra->table, ra->chain, ra->parameters};
    uint64_t pos = ra->position;
    ra->uuid = rb->uuid;
    ra->table = rb->table;
    ra->chain = rb->chain;
    ra->parameters = rb->parameters;
    ra->position = rb->position;
    bool eq = ks_schema_equal(&ks_fw_rule_schema, ra, rb);
    ra->uuid = saved[0];
    ra->table = saved[1];
    ra->chain = saved[2];
    ra->parameters = saved[3];
    ra->position = pos;
    return eq;
}

bool ks_fws_from_flat(const struct ks_fw_chain *flat, struct ks_fws_rule *out)
{
    struct ks_fwf_form f;
    char err[512];
    if (ks_fwf_from_rule(flat, &no_services, &f, err, sizeof(err)) < 0 || !from_form(&f, out))
        return false;
    struct ks_fw_chain back;
    if (ks_fws_to_flat(out, &back, err, sizeof(err)) < 0)
        return false;
    bool same = same_flat(&back, flat);
    ks_fwr_free_chain(&back);
    return same;
}

/* ---- rows ------------------------------------------------------------------ */

static bool policy_rule(const char *uuid)
{
    /* the rules of the drop profiles (ProfileDropInput, ProfileDropOutput) */
    static const enum ks_fw_profile ps[] = {KS_FW_PROFILE_DROP_INPUT, KS_FW_PROFILE_DROP_OUTPUT};
    bool found = false;
    for (size_t p = 0; p < 2 && !found; p++) {
        struct ks_fw_chain c;
        if (ks_fwr_profile(ps[p], &c) < 0)
            continue;
        for (size_t i = 0; i < c.rules.len && !found; i++)
            found = seq(KS_SYSFW_RULE(&c, i)->uuid, uuid);
        ks_fwr_free_chain(&c);
    }
    return found;
}

int ks_fws_rows(const struct ks_sysfw *fw, struct ks_fws_rows *out)
{
    memset(out, 0, sizeof(*out));
    if (fw == NULL)
        return 0;
    size_t cap = 0;
    for (size_t l = 0; l < fw->system_rules.len; l++) {
        const struct ks_fw_chains_list *list = KS_SYSFW_RULES(fw, l);
        for (size_t c = 0; c < list->chains.len; c++) {
            const struct ks_fw_chain *ch = KS_SYSFW_CHAIN(list, c);
            for (size_t i = 0; i < ch->rules.len; i++) {
                const struct ks_fw_rule *r = KS_SYSFW_RULE(ch, i);
                if (out->n == cap) {
                    cap = cap ? cap * 2 : 16;
                    struct ks_fws_row *v = realloc(out->v, cap * sizeof(*v));
                    if (v == NULL) {
                        ks_fws_rows_free(out);
                        return -1;
                    }
                    out->v = v;
                }
                struct ks_fws_row *row = &out->v[out->n++];
                memset(row, 0, sizeof(*row));
                copy(row->uuid, sizeof(row->uuid), r->uuid);
                copy(row->chain, sizeof(row->chain), ch->name);
                row->enabled = r->enabled;
                /* a flat copy, as get_rule_by_uuid makes */
                struct ks_fw_chain flat = *ch;
                flat.rules.items = (void *)(uintptr_t)r;
                flat.rules.len = 1;
                flat.rules.non_nil = true;
                if (policy_rule(r->uuid))
                    row->kind = KS_FWS_ROW_POLICY;
                else if (ks_fws_from_flat(&flat, &row->rule))
                    row->kind = KS_FWS_ROW_SIMPLE;
                else
                    row->kind = KS_FWS_ROW_ADVANCED;
                if (row->kind != KS_FWS_ROW_SIMPLE) {
                    char *cols[KS_FWR_NCOLS] = {0};
                    if (ks_fwr_to_array("", ch, r, cols) == 0) {
                        /* the description, or the expressions, and the target */
                        snprintf(row->summary, sizeof(row->summary), "%s -> %s%s%s",
                                 cols[7][0] ? cols[7] : cols[8], cols[9],
                                 cols[10][0] ? " " : "", cols[10]);
                    }
                    for (int k = 0; k < KS_FWR_NCOLS; k++)
                        free(cols[k]);
                }
            }
        }
    }
    return 0;
}

void ks_fws_rows_free(struct ks_fws_rows *rows)
{
    free(rows->v);
    memset(rows, 0, sizeof(*rows));
}

const char *ks_fws_action_text(int action)
{
    return action == KS_FWS_DENY ? _("Deny") : action == KS_FWS_REJECT ? _("Reject") : _("Allow");
}

const char *ks_fws_direction_text(int direction)
{
    return direction == KS_FWS_OUT ? _("Out") : _("In");
}

void ks_fws_port_text(const struct ks_fws_rule *r, char *buf, size_t len)
{
    if (r->proto < 0) {
        snprintf(buf, len, "%s", _("Any"));
        return;
    }
    const char *p = r->proto == 0 ? "tcp+udp" : ks_fw_port_protocols[r->proto];
    snprintf(buf, len, "%s%s%s", p, r->port[0] ? " " : "", r->port);
}

void ks_fws_addr_text(const char *addr, char *buf, size_t len)
{
    copy(buf, len, addr);
    const char *dash = strchr(addr, '-');
    if (dash == NULL || strchr(dash + 1, '-') != NULL)
        return;
    char a[64], b[64];
    size_t al = (size_t)(dash - addr);
    if (al >= sizeof(a) || strlen(dash + 1) >= sizeof(b))
        return;
    memcpy(a, addr, al);
    a[al] = '\0';
    copy(b, sizeof(b), dash + 1);
    unsigned char x[16], y[16];
    int fam = strchr(a, ':') != NULL ? AF_INET6 : AF_INET;
    size_t n = fam == AF_INET6 ? 16 : 4;
    if (inet_pton(fam, a, x) != 1 || inet_pton(fam, b, y) != 1)
        return;
    /* the first bit where they differ starts the host part: from there,
     * the first address must be all zeros and the last all ones */
    size_t prefix = n * 8;
    for (size_t bit = 0; bit < n * 8; bit++) {
        int bx = (x[bit / 8] >> (7 - bit % 8)) & 1, by = (y[bit / 8] >> (7 - bit % 8)) & 1;
        if (bx != by) {
            prefix = bit;
            break;
        }
    }
    for (size_t bit = prefix; bit < n * 8; bit++) {
        int bx = (x[bit / 8] >> (7 - bit % 8)) & 1, by = (y[bit / 8] >> (7 - bit % 8)) & 1;
        if (bx != 0 || by != 1)
            return;
    }
    snprintf(buf, len, "%s/%zu", a, prefix);
}

/* ---- policies ------------------------------------------------------------- */

int ks_fws_policy(const struct ks_sysfw *fw, int direction, bool *drop)
{
    const char *p = direction == KS_FWS_OUT ? ks_fwr_get_policy(fw, "output", "mangle", "inet")
                                            : ks_fwr_get_policy(fw, "input", "filter", "inet");
    if (p == NULL)
        return -1;
    *drop = strcmp(p, "drop") == 0;
    return 0;
}

int ks_fws_set_policy(struct ks_sysfw *fw, int direction, bool drop, const char **err)
{
    bool out = direction == KS_FWS_OUT;
    struct ks_fw_chain prof;
    if (!drop) {
        if (ks_fwr_profile(out ? KS_FW_PROFILE_DROP_OUTPUT : KS_FW_PROFILE_DROP_INPUT, &prof) == 0) {
            ks_fwr_delete_profile(fw, &prof);
            ks_fwr_free_chain(&prof);
        }
    }
    enum ks_fw_profile want = out ? (drop ? KS_FW_PROFILE_DROP_OUTPUT : KS_FW_PROFILE_ACCEPT_OUTPUT)
                                  : (drop ? KS_FW_PROFILE_DROP_INPUT : KS_FW_PROFILE_ACCEPT_INPUT);
    if (ks_fwr_profile(want, &prof) < 0) {
        *err = "out of memory";
        return -1;
    }
    int r = ks_fwr_apply_profile(fw, &prof, err);
    ks_fwr_free_chain(&prof);
    return r;
}

/* ---- editing -------------------------------------------------------------- */

int ks_fws_save(struct ks_sysfw *fw, const struct ks_fws_rule *r, char *err, size_t errlen)
{
    struct ks_fw_chain flat;
    if (ks_fws_to_flat(r, &flat, err, errlen) < 0)
        return -1;
    const char *e = NULL;
    int ret;
    if (r->uuid[0] != '\0' && ks_fwr_find(fw, r->uuid, NULL) != NULL) {
        /* the same chain: update in place; another one (the direction
         * changed): delete and add */
        struct ks_fw_chain *ch = NULL;
        ks_fwr_find(fw, r->uuid, &ch);
        if (ch != NULL && seq(ch->name, flat.name) && seq(ch->hook, flat.hook)) {
            ret = ks_fwr_update(fw, r->uuid, &flat, &e);
        } else {
            ks_fwr_delete(fw, r->uuid);
            ret = ks_fwr_add(fw, &flat, &e);
        }
    } else {
        ret = ks_fwr_add(fw, &flat, &e);
    }
    if (ret < 0)
        snprintf(err, errlen, "%s", e != NULL ? e : "error saving the rule");
    ks_fwr_free_chain(&flat);
    return ret;
}

bool ks_fws_move(struct ks_sysfw *fw, const char *uuid, int delta)
{
    struct ks_fw_chain *ch = NULL;
    if (ks_fwr_find(fw, uuid, &ch) == NULL || ch == NULL)
        return false;
    for (size_t i = 0; i < ch->rules.len; i++) {
        if (!seq(KS_SYSFW_RULE(ch, i)->uuid, uuid))
            continue;
        if ((delta < 0 && i == 0) || (delta > 0 && i + 1 >= ch->rules.len))
            return false;
        return ks_fwr_swap(fw, uuid, i, delta < 0 ? i - 1 : i + 1);
    }
    return false;
}

/* ---- ufw application profiles -------------------------------------------- */

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = '\0';
    return s;
}

/* "80,443", "6000:6007": digits, commas and ranges; ':' becomes '-' */
static bool ufw_ports(const char *in, char *out, size_t len)
{
    size_t o = 0;
    bool digit = false;
    for (const char *c = in; *c; c++) {
        char ch = *c;
        if (ch >= '0' && ch <= '9')
            digit = true;
        else if (ch == ':')
            ch = '-';
        else if (ch != ',')
            return false;
        if (o + 1 >= len)
            return false;
        out[o++] = ch;
    }
    out[o] = '\0';
    return digit;
}

static void add_app(struct ks_fws_apps *apps, const char *section, const char *title,
                    const char *ports)
{
    char buf[KS_FWS_TEXT_MAX];
    copy(buf, sizeof(buf), ports);
    size_t entries = 1;
    for (const char *c = buf; *c; c++)
        entries += *c == '|';
    char *save = NULL;
    for (char *e = strtok_r(buf, "|", &save); e != NULL; e = strtok_r(NULL, "|", &save)) {
        e = trim(e);
        char *slash = strchr(e, '/');
        int proto = 0; /* no protocol: both */
        if (slash != NULL) {
            *slash = '\0';
            proto = ks_fw_index_of(ks_fw_port_protocols, KS_FW_NPORT_PROTOCOLS, trim(slash + 1));
            if (proto <= 0)
                continue;
        }
        struct ks_fws_app a;
        memset(&a, 0, sizeof(a));
        if (!ufw_ports(trim(e), a.ports, sizeof(a.ports)))
            continue;
        a.proto = proto;
        copy(a.title, sizeof(a.title), title);
        if (entries > 1)
            snprintf(a.name, sizeof(a.name), "%.120s (%.60s%s%.10s)", section, a.ports,
                     proto ? "/" : "", proto ? ks_fw_port_protocols[proto] : "");
        else
            copy(a.name, sizeof(a.name), section);
        struct ks_fws_app *v = realloc(apps->v, (apps->n + 1) * sizeof(*v));
        if (v == NULL)
            return;
        apps->v = v;
        apps->v[apps->n++] = a;
    }
}

void ks_fws_apps_parse(struct ks_fws_apps *apps, const char *text)
{
    char *copyt = strdup(text != NULL ? text : "");
    if (copyt == NULL)
        return;
    char section[KS_FWS_TEXT_MAX] = "", title[KS_FWS_TEXT_MAX] = "", ports[KS_FWS_TEXT_MAX] = "";
    char *save = NULL;
    for (char *line = strtok_r(copyt, "\n", &save);; line = strtok_r(NULL, "\n", &save)) {
        char *l = line != NULL ? trim(line) : NULL;
        if (l == NULL || l[0] == '[') {
            if (section[0] && ports[0])
                add_app(apps, section, title, ports);
            if (l == NULL)
                break;
            char *end = strchr(l, ']');
            if (end != NULL)
                *end = '\0';
            copy(section, sizeof(section), trim(l + 1));
            title[0] = ports[0] = '\0';
            continue;
        }
        if (l[0] == '#' || l[0] == ';' || l[0] == '\0')
            continue;
        char *eq = strchr(l, '=');
        if (eq == NULL)
            eq = strchr(l, ':');
        if (eq == NULL)
            continue;
        *eq = '\0';
        char *k = trim(l), *v = trim(eq + 1);
        if (strcasecmp(k, "title") == 0)
            copy(title, sizeof(title), v);
        else if (strcasecmp(k, "ports") == 0)
            copy(ports, sizeof(ports), v);
    }
    free(copyt);
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void ks_fws_apps_load(struct ks_fws_apps *apps, const char *dir)
{
    memset(apps, 0, sizeof(*apps));
    if (dir == NULL)
        dir = "/etc/ufw/applications.d";
    DIR *d = opendir(dir);
    if (d == NULL)
        return;
    char **names = NULL;
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char **v = realloc(names, (n + 1) * sizeof(*v));
        if (v == NULL)
            break;
        names = v;
        if ((names[n] = strdup(e->d_name)) != NULL)
            n++;
    }
    closedir(d);
    if (n > 0)
        qsort(names, n, sizeof(*names), cmp_names);
    for (size_t i = 0; i < n; i++) {
        char path[4096], err[256];
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        size_t len;
        char *text = ks_read_file(path, 1024 * 1024, &len, err, sizeof(err));
        if (text != NULL)
            ks_fws_apps_parse(apps, text);
        free(text);
        free(names[i]);
    }
    free(names);
}

void ks_fws_apps_free(struct ks_fws_apps *apps)
{
    free(apps->v);
    memset(apps, 0, sizeof(*apps));
}
