/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/main.go onPacket(), acceptOrDeny() and
 * applyDefaultAction(), and conman.Parse() (daemon/conman/connection.go).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/intercept.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/conn.h"
#include "daemon/dns/cache.h"
#include "daemon/procmon/procmon.h"
#include "daemon/rules/loader.h"
#include "daemon/sockdiag.h"
#include "daemon/stats.h"
#include "daemon/uiclient.h"

void ks_intercept_init(struct ks_intercept *ic, struct ks_loader *rules)
{
    memset(ic, 0, sizeof(*ic));
    ic->rules = rules;
    snprintf(ic->default_action, sizeof(ic->default_action), "%s", KS_ACTION_ALLOW);
    ic->own_pid = getpid();
    struct stat st;
    ic->ipv6_enabled = stat("/proc/sys/net/ipv6", &st) == 0;
}

void ks_intercept_set_default_action(struct ks_intercept *ic, const char *action)
{
    if (action != NULL && action[0] != '\0')
        snprintf(ic->default_action, sizeof(ic->default_action), "%s", action);
}

/* A connection being decided: conman.Connection plus what keeps its
 * borrowed fields alive. */
struct con {
    struct ks_conn c;
    struct ks_packet pkt;
    struct ks_procmon_result owner;
    char *dst_host; /* owned; c.dst_host points here (or to "") */
};

static void con_clear(struct con *con)
{
    ks_procmon_result_clear(&con->owner);
    free(con->dst_host);
    con->dst_host = NULL;
}

static void accept_mark(uint32_t mark, struct ks_verdict *v)
{
    v->verdict = KS_NF_ACCEPT; /* SetVerdictAndMark(NF_ACCEPT, packet.Mark) */
    v->mark = mark;
}

static void drop(struct ks_verdict *v)
{
    v->verdict = KS_NF_DROP; /* SetVerdict(NF_DROP) */
    v->mark = 0;
}

/* uiClient.DefaultAction() */
static const char *default_action(const struct ks_intercept *ic)
{
    return ic->ui ? ks_uiclient_default_action(ic->ui) : ic->default_action;
}

static bool intercept_unknown(const struct ks_intercept *ic)
{
    return ic->ui ? ks_uiclient_intercept_unknown(ic->ui) : ic->intercept_unknown;
}

/* applyDefaultAction */
static void apply_default_action(struct ks_intercept *ic, uint32_t mark,
                                 const struct con *con, struct ks_verdict *v)
{
    const char *action = default_action(ic);
    ks_trace("Applying DefaultAction (%s)", action);
    if (strcmp(action, KS_ACTION_ALLOW) == 0) {
        v->verdict = KS_NF_ACCEPT;
        v->mark = mark;
        return;
    }
    if (strcmp(action, KS_ACTION_REJECT) == 0 && con != NULL)
        ks_kill_socket(con->c.protocol, &con->c.src_ip, con->c.src_port, &con->c.dst_ip,
                       con->c.dst_port);
    drop(v);
}

/* conman.Parse + newConnectionImpl (proc method), from the already
 * decoded con->pkt. Returns 0 with `con` filled, or -1: no connection
 * (upstream returns nil). */
static int parse(struct ks_intercept *ic, const struct ks_nfq_packet *p, struct con *con)
{
    if (!con->pkt.ipv4 && !ic->ipv6_enabled)
        return -1;

    struct ks_conn *c = &con->c;
    c->src_ip = con->pkt.src;
    c->dst_ip = con->pkt.dst;
    /* NewConnection(6): DstHost: dns.HostOr(ip.DstIP, "") */
    con->dst_host = ks_dns_host_or(&c->dst_ip, "");
    c->protocol = ks_packet_protocol(&con->pkt);
    if (c->protocol == NULL) { /* parseDirection: not enough info */
        ks_trace("discarding connection");
        return -1;
    }
    c->src_port = con->pkt.sport;
    c->dst_port = con->pkt.dport;
    /* getDomains(): a DNS query names the host being resolved. Over TCP
     * gopacket never decodes DNS (DecodeStreamsAsDatagrams is off). */
    if (con->pkt.l4 == KS_L4_UDP && con->pkt.dport == 53) {
        char *q = ks_dns_query_domain(&con->pkt);
        if (q != NULL) {
            free(con->dst_host);
            con->dst_host = q;
        }
    }
    c->dst_host = con->dst_host != NULL ? con->dst_host : "";
    c->iface_in = (int)p->indev;
    c->iface_out = (int)p->outdev;

    if (ks_log_get_level() <= KS_LOG_DEBUG) {
        char src[KS_IP_STRLEN], dst[KS_IP_STRLEN];
        ks_ip_string(&c->src_ip, src, sizeof(src));
        ks_ip_string(&c->dst_ip, dst, sizeof(dst));
        ks_debug("new connection %s => %u:%s -> %s (%s):%u uid: %u, mark: %x", c->protocol,
                 c->src_port, src, dst, c->dst_host, c->dst_port, p->uid, p->mark);
    }

    if (ks_procmon_resolve(c->protocol, &c->src_ip, c->src_port, &c->dst_ip, c->dst_port,
                           p->uid, intercept_unknown(ic), &con->owner) < 0)
        return -1;
    c->uid = con->owner.uid;
    c->process = &con->owner.proc->view;
    return 0;
}

/* The verdict for a connection `r` matched (the second half of
 * acceptOrDeny). */
static void verdict_for_rule(struct ks_intercept *ic, uint32_t mark, struct con *con,
                             const struct ks_rule *r, struct ks_verdict *v)
{
    char desc[1024];
    if (!r->enabled) {
        apply_default_action(ic, mark, con, v);
        ks_conn_string(&con->c, desc, sizeof(desc));
        ks_info("DISABLED (%s) %s (%s)", default_action(ic), desc, r->name);
    } else if (strcmp(r->action, KS_ACTION_ALLOW) == 0) {
        accept_mark(mark, v);
        if (ks_log_get_level() <= KS_LOG_DEBUG) {
            ks_conn_string(&con->c, desc, sizeof(desc));
            ks_debug("✔ %s, mark: %x (%s)", desc, mark, r->name);
        }
    } else {
        if (strcmp(r->action, KS_ACTION_REJECT) == 0)
            ks_kill_socket(con->c.protocol, &con->c.src_ip, con->c.src_port,
                           &con->c.dst_ip, con->c.dst_port);
        drop(v);
        if (ks_log_get_level() <= KS_LOG_DEBUG) {
            ks_conn_string(&con->c, desc, sizeof(desc));
            ks_debug("✘ %s, mark: %x (%s)", desc, mark, r->name);
        }
    }
}

/* The end of onPacket(): the connection goes to the stats unless its rule
 * says nolog. */
static void on_connection_event(struct ks_intercept *ic, struct con *con,
                                const struct ks_rule *r)
{
    if (r != NULL && r->nolog)
        return;
    if (ic->stats)
        ks_stats_on_connection(ic->stats, &con->c, con->owner.proc, r, r == NULL);
}

/* A question to the UI in flight: the connection and its packet. */
struct pending {
    struct ks_intercept *ic;
    uint32_t id, mark;
    struct con con;
};

/* The rest of acceptOrDeny once the UI answered. `rule` is ours. */
static void on_answer(struct ks_rule *rule, void *data)
{
    struct pending *pd = data;
    struct ks_intercept *ic = pd->ic;
    struct ks_verdict v;
    if (rule == NULL) {
        ks_error("Invalid rule received, applying default action");
        apply_default_action(ic, pd->mark, &pd->con, &v);
        ic->deferred(pd->id, &v, ic->deferred_data);
        on_connection_event(ic, &pd->con, NULL);
        con_clear(&pd->con);
        free(pd);
        return;
    }

    /* check if and how the rule needs to be saved */
    bool always = strcmp(rule->duration, "always") == 0;
    const char *pers = always ? "Saved" : "Added";
    char err[512], op[512];
    ks_operator_describe(&rule->operator, op, sizeof(op));
    struct ks_rule *copy = ks_rule_copy(rule);
    if (copy == NULL || ks_loader_add(ic->rules, copy, always, err, sizeof(err)) < 0)
        ks_error("Error while %s rule: %s", always ? "saving" : "adding",
                 copy ? err : "out of memory");
    else
        ks_important("%s new rule: %s if %s", pers, rule->action, op);

    verdict_for_rule(ic, pd->mark, &pd->con, rule, &v);
    ic->deferred(pd->id, &v, ic->deferred_data);
    on_connection_event(ic, &pd->con, rule);
    ks_rule_free(rule);
    con_clear(&pd->con);
    free(pd);
}

/* acceptOrDeny(). Returns false if the verdict was deferred (the UI was
 * asked; `con` then belongs to the question). Otherwise `*match` is the
 * rule that decided it, or NULL. */
static bool accept_or_deny(struct ks_intercept *ic, const struct ks_nfq_packet *p,
                           struct con *con, struct ks_verdict *v,
                           const struct ks_rule **match)
{
    const struct ks_rule *r = ks_loader_find_first_match(ic->rules, &con->c);
    *match = r;
    if (r != NULL) {
        verdict_for_rule(ic, p->mark, con, r, v);
        return true;
    }

    /* send a request to the UI client if 1) connected and running and 2) we
     * are not already asking */
    bool connected = ic->ui != NULL && ks_uiclient_connected(ic->ui);
    bool asking = ic->ui != NULL && ks_uiclient_is_asking(ic->ui);
    if (!connected || asking) {
        apply_default_action(ic, p->mark, con, v);
        ks_debug("UI is not running or busy, connected: %s, running: %s",
                 connected ? "true" : "false", asking ? "true" : "false");
        return true;
    }

    struct pending *pd = malloc(sizeof(*pd));
    if (pd == NULL) {
        apply_default_action(ic, p->mark, con, v);
        return true;
    }
    pd->ic = ic;
    pd->id = p->id;
    pd->mark = p->mark;
    pd->con = *con; /* moves the strings and the process reference */
    /* Update the hostname again: a DNS answer may have arrived meanwhile. */
    if (pd->con.c.dst_host[0] == '\0') {
        char *h = ks_dns_host_or(&pd->con.c.dst_ip, "");
        if (h != NULL) {
            free(pd->con.dst_host);
            pd->con.dst_host = h;
            pd->con.c.dst_host = h;
        }
    }
    if (ks_uiclient_ask(ic->ui, &pd->con.c, pd->con.owner.proc, on_answer, pd) < 0) {
        /* Ask() returned nil */
        *con = pd->con;
        free(pd);
        ks_error("Invalid rule received, applying default action");
        apply_default_action(ic, p->mark, con, v);
        return true;
    }
    memset(con, 0, sizeof(*con));
    return false;
}

bool ks_intercept_packet(struct ks_intercept *ic, const struct ks_nfq_packet *p,
                         struct ks_verdict *out)
{
    struct con con;
    memset(&con, 0, sizeof(con));

    /* DNS response, just parse, track and accept. */
    ks_packet_decode(p->data, p->len, &con.pkt);
    if (ks_dns_track_answers(&con.pkt)) {
        accept_mark(p->mark, out);
        if (ic->stats)
            ks_stats_on_dns_response(ic->stats);
        return true;
    }

    if (parse(ic, p, &con) < 0) {
        apply_default_action(ic, p->mark, NULL, out);
        con_clear(&con);
        return true;
    }
    /* accept our own connections */
    if (con.owner.proc->pid == ic->own_pid) {
        out->verdict = KS_NF_ACCEPT; /* SetVerdict(NF_ACCEPT): mark 0 */
        out->mark = 0;
        con_clear(&con);
        return true;
    }
    const struct ks_rule *r;
    if (!accept_or_deny(ic, p, &con, out, &r))
        return false;
    on_connection_event(ic, &con, r);
    con_clear(&con);
    return true;
}
