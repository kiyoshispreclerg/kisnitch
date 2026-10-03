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
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/log.h"
#include "daemon/conn.h"
#include "daemon/procmon/procmon.h"
#include "daemon/rules/loader.h"
#include "daemon/sockdiag.h"

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
};

static void con_string(const struct con *con, char *buf, size_t len)
{
    char dst[KS_IP_STRLEN];
    ks_ip_string(&con->c.dst_ip, dst, sizeof(dst));
    const struct ks_proc *p = con->owner.proc;
    snprintf(buf, len, "%s (%d) -> %s:%u (proto:%s uid:%lld)", p && p->path ? p->path : "",
             p ? p->pid : -1, dst, con->c.dst_port, con->c.protocol, con->c.uid);
}

static void accept_mark(const struct ks_nfq_packet *p, struct ks_verdict *v)
{
    v->verdict = KS_NF_ACCEPT; /* SetVerdictAndMark(NF_ACCEPT, packet.Mark) */
    v->mark = p->mark;
}

static void drop(struct ks_verdict *v)
{
    v->verdict = KS_NF_DROP; /* SetVerdict(NF_DROP) */
    v->mark = 0;
}

/* applyDefaultAction */
static void apply_default_action(struct ks_intercept *ic, const struct ks_nfq_packet *p,
                                 const struct con *con, struct ks_verdict *v)
{
    ks_trace("Applying DefaultAction (%s)", ic->default_action);
    if (strcmp(ic->default_action, KS_ACTION_ALLOW) == 0) {
        accept_mark(p, v);
        return;
    }
    if (strcmp(ic->default_action, KS_ACTION_REJECT) == 0 && con != NULL)
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
    c->protocol = ks_packet_protocol(&con->pkt);
    if (c->protocol == NULL) { /* parseDirection: not enough info */
        ks_trace("discarding connection");
        return -1;
    }
    c->src_ip = con->pkt.src;
    c->dst_ip = con->pkt.dst;
    c->src_port = con->pkt.sport;
    c->dst_port = con->pkt.dport;
    c->dst_host = ""; /* dns.HostOr(): phase 4 */
    c->iface_in = (int)p->indev;
    c->iface_out = (int)p->outdev;

    if (ks_log_get_level() <= KS_LOG_DEBUG) {
        char src[KS_IP_STRLEN], dst[KS_IP_STRLEN];
        ks_ip_string(&c->src_ip, src, sizeof(src));
        ks_ip_string(&c->dst_ip, dst, sizeof(dst));
        ks_debug("new connection %s => %u:%s -> %s ():%u uid: %u, mark: %x", c->protocol,
                 c->src_port, src, dst, c->dst_port, p->uid, p->mark);
    }

    if (ks_procmon_resolve(c->protocol, &c->src_ip, c->src_port, &c->dst_ip, c->dst_port,
                           p->uid, ic->intercept_unknown, &con->owner) < 0)
        return -1;
    c->uid = con->owner.uid;
    c->process = &con->owner.proc->view;
    return 0;
}

/* acceptOrDeny, without the UI (phase 5): no match -> default action. */
static const struct ks_rule *accept_or_deny(struct ks_intercept *ic,
                                            const struct ks_nfq_packet *p, struct con *con,
                                            struct ks_verdict *v)
{
    const struct ks_rule *r = ks_loader_find_first_match(ic->rules, &con->c);
    if (r == NULL) {
        apply_default_action(ic, p, con, v);
        ks_debug("UI is not running or busy, connected: false, running: false");
        return NULL;
    }

    char desc[1024];
    if (!r->enabled) {
        apply_default_action(ic, p, con, v);
        con_string(con, desc, sizeof(desc));
        ks_info("DISABLED (%s) %s (%s)", ic->default_action, desc, r->name);
    } else if (strcmp(r->action, KS_ACTION_ALLOW) == 0) {
        accept_mark(p, v);
        if (ks_log_get_level() <= KS_LOG_DEBUG) {
            con_string(con, desc, sizeof(desc));
            ks_debug("✔ %s, mark: %x (%s)", desc, p->mark, r->name);
        }
    } else {
        if (strcmp(r->action, KS_ACTION_REJECT) == 0)
            ks_kill_socket(con->c.protocol, &con->c.src_ip, con->c.src_port,
                           &con->c.dst_ip, con->c.dst_port);
        drop(v);
        if (ks_log_get_level() <= KS_LOG_DEBUG) {
            con_string(con, desc, sizeof(desc));
            ks_debug("✘ %s, mark: %x (%s)", desc, p->mark, r->name);
        }
    }
    return r;
}

void ks_intercept_packet(struct ks_intercept *ic, const struct ks_nfq_packet *p,
                         struct ks_verdict *out)
{
    struct con con;
    memset(&con, 0, sizeof(con));

    /* DNS response: accepted (and, from phase 4 on, parsed and tracked).
     * dns.TrackAnswers() needs a UDP layer from port 53 and a DNS layer,
     * which gopacket only decodes from a non-empty payload. */
    ks_packet_decode(p->data, p->len, &con.pkt);
    if (con.pkt.l4 == KS_L4_UDP && con.pkt.sport == 53 && con.pkt.udp_payload_len > 0) {
        accept_mark(p, out);
        return;
    }

    if (parse(ic, p, &con) < 0) {
        apply_default_action(ic, p, NULL, out);
        return;
    }
    /* accept our own connections */
    if (con.owner.proc->pid == ic->own_pid) {
        out->verdict = KS_NF_ACCEPT; /* SetVerdict(NF_ACCEPT): mark 0 */
        out->mark = 0;
        ks_procmon_result_clear(&con.owner);
        return;
    }
    accept_or_deny(ic, p, &con, out);
    ks_procmon_result_clear(&con.owner);
}
