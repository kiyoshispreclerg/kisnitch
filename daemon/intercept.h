/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The verdict on each queued packet. Port of upstream daemon/main.go
 * onPacket(), acceptOrDeny() and applyDefaultAction(), with
 * conman.Parse()/newConnectionImpl() (daemon/conman/connection.go), and
 * the DNS hooks: responses are tracked and accepted (dns.TrackAnswers()),
 * and each connection gets its DstHost (dns.HostOr(), or the name asked
 * for in a DNS query).
 *
 * Without a UI (phase 5), a connection no rule matches gets the
 * configured DefaultAction, as upstream does while the UI is disconnected.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_intercept borrows the rules loader, which must outlive
 * it; it copies the default action.
 */
#ifndef KS_DAEMON_INTERCEPT_H
#define KS_DAEMON_INTERCEPT_H

#include <stdbool.h>
#include <stdint.h>

#include "daemon/queue.h"

struct ks_loader;

struct ks_intercept {
    struct ks_loader *rules;
    /* clientDisconnectedRule.Action: "allow" unless the configuration's
     * DefaultAction says otherwise. */
    char default_action[16];
    bool intercept_unknown; /* InterceptUnknown */
    bool ipv6_enabled;      /* core.IPv6Enabled */
    int own_pid;
};

/* What to answer the kernel. */
struct ks_verdict {
    uint32_t verdict; /* KS_NF_ACCEPT or KS_NF_DROP */
    uint32_t mark;
};

/* Fills in the defaults: allow, our PID, IPv6 if /proc/sys/net/ipv6 exists. */
void ks_intercept_init(struct ks_intercept *ic, struct ks_loader *rules);

/* Config.DefaultAction (ignored when empty, like upstream). */
void ks_intercept_set_default_action(struct ks_intercept *ic, const char *action);

/* onPacket(): decides `p`. A "reject" also destroys the socket. */
void ks_intercept_packet(struct ks_intercept *ic, const struct ks_nfq_packet *p,
                         struct ks_verdict *out);

#endif
