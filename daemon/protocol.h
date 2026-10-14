/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Conversions between the daemon's structures and the protocol messages
 * (proto/ui.proto). Port of upstream rule.Rule.Serialize() and
 * rule.Deserialize() (daemon/rule/rule.go), conman.Connection.Serialize()
 * (daemon/conman/connection.go) and ui.NewAlert() (daemon/ui/alerts.go).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: messages built here live in the struct ks_arena passed in, and
 * their strings may also point into the source structures (rule, process),
 * which must outlive the message. Pack them, then free the arena.
 */
#ifndef KS_DAEMON_PROTOCOL_H
#define KS_DAEMON_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/arena.h"
#include "common/pb_util.h"
#include "common/pb/ui.pb-c.h"
#include "daemon/conn.h"

struct ks_rule;
struct ks_proc;

/* Rule.Serialize(). NULL `r` gives NULL, like upstream. */
Protocol__Rule *ks_pb_rule(struct ks_arena *a, const struct ks_rule *r);

/* rule.Deserialize(): a new, uncompiled rule; Created is now. NULL with
 * `err` filled if the message has no operator. */
struct ks_rule *ks_rule_from_pb(const Protocol__Rule *pr, char *err, size_t errlen);

/* Connection.Serialize(). `proc` is the connection's process (the one
 * c->process views); its path, args, env, cwd, checksums and tree are
 * borrowed. */
Protocol__Connection *ks_pb_connection(struct ks_arena *a, const struct ks_conn *c,
                                       const struct ks_proc *proc);

/* NewAlert() with text data (What GENERIC, or KERNEL_EVENT, which also
 * forces Action SHOW_ALERT). */
Protocol__Alert *ks_pb_alert_text(struct ks_arena *a, Protocol__Alert__Type type,
                                  Protocol__Alert__What what,
                                  Protocol__Alert__Action action,
                                  Protocol__Alert__Priority prio, const char *text);

/* time.Parse(time.RFC3339, s).Unix(). -1 on error. */
int ks_parse_rfc3339(const char *s, int64_t *unix_out);

/* time.Now().UnixNano(), the IDs upstream gives to alerts and pings. */
uint64_t ks_unix_nano(void);

#endif
