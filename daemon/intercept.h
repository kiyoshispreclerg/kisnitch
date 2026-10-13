/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The verdict on each queued packet. Port of upstream daemon/main.go
 * onPacket(), acceptOrDeny() and applyDefaultAction(), with
 * conman.Parse()/newConnectionImpl() (daemon/conman/connection.go), and
 * the DNS hooks: responses are tracked and accepted (dns.TrackAnswers()),
 * and each connection gets its DstHost (dns.HostOr(), or the name asked
 * for in a DNS query).
 *
 * A connection no rule matches is sent to the UI, if it's connected and
 * not busy with another question; the packet's verdict then comes later,
 * through the `deferred` callback, once the UI answers (or the question
 * fails or times out: DefaultAction). Upstream gets there by requeueing the
 * packet to queue+1 while the goroutine waits; we just hold the packet id.
 * Without a UI, or while it's busy, the connection gets DefaultAction.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_intercept borrows the rules loader, the UI client and
 * the stats, which must outlive it; it copies the default action. A
 * connection waiting for the UI is owned by the pending question.
 */
#ifndef KS_DAEMON_INTERCEPT_H
#define KS_DAEMON_INTERCEPT_H

#include <stdbool.h>
#include <stdint.h>

#include "daemon/queue.h"

struct ks_loader;
struct ks_stats;
struct ks_uiclient;

/* What to answer the kernel. */
struct ks_verdict {
    uint32_t verdict; /* KS_NF_ACCEPT or KS_NF_DROP */
    uint32_t mark;
};

/* A verdict decided after ks_intercept_packet() returned. */
typedef void (*ks_deferred_verdict_cb)(uint32_t packet_id, const struct ks_verdict *v,
                                       void *data);

struct ks_intercept {
    struct ks_loader *rules;
    /* Optional. Without a UI client, DefaultAction is `default_action` and
     * InterceptUnknown is `intercept_unknown`; with one, both come from
     * it. */
    struct ks_uiclient *ui;
    struct ks_stats *stats; /* optional */
    ks_deferred_verdict_cb deferred;
    void *deferred_data;
    /* clientDisconnectedRule.Action: "allow" unless the configuration's
     * DefaultAction says otherwise. */
    char default_action[16];
    bool intercept_unknown; /* InterceptUnknown */
    bool ipv6_enabled;      /* core.IPv6Enabled */
    int own_pid;
};

/* Fills in the defaults: allow, our PID, IPv6 if /proc/sys/net/ipv6 exists. */
void ks_intercept_init(struct ks_intercept *ic, struct ks_loader *rules);

/* Config.DefaultAction (ignored when empty, like upstream). */
void ks_intercept_set_default_action(struct ks_intercept *ic, const char *action);

/* onPacket(): decides `p`. A "reject" also destroys the socket. Returns
 * true with the verdict in `out`, or false if the UI was asked: the
 * verdict will come through ic->deferred. */
bool ks_intercept_packet(struct ks_intercept *ic, const struct ks_nfq_packet *p,
                         struct ks_verdict *out);

#endif
