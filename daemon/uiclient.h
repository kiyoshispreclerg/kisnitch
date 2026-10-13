/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The daemon's side of the UI protocol. Port of upstream daemon/ui/:
 * client.go (connection poller, Ping, AskRule, the default actions),
 * notifications.go (Subscribe, the Notifications stream and its actions),
 * alerts.go (PostAlert and the queue of alerts while disconnected) and
 * config_utils.go (loading, watching and applying default-config.json).
 *
 * Everything runs on the event loop. Where upstream blocks a goroutine on
 * an RPC, the call is started and its result handled in a callback.
 *
 * Not ported yet, see docs/UPSTREAM.md: TLS authentication (phase 10),
 * the system firewall in Subscribe/RELOAD_FW_RULES (phase 8), tasks
 * (TASK_START/TASK_STOP, phase 10) and loggers (phase 10).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_uiclient owns its configuration, its gRPC connection,
 * its timers and watchers on the loop, and the queued alerts. The loop,
 * the rules loader, the stats and the firewall are borrowed and must
 * outlive it.
 */
#ifndef KS_DAEMON_UICLIENT_H
#define KS_DAEMON_UICLIENT_H

#include <stdbool.h>
#include <stddef.h>

#include "common/pb/ui.pb-c.h"
#include "daemon/config.h"
#include "daemon/conn.h"

struct ks_evloop;
struct ks_loader;
struct ks_stats;
struct ks_fw;
struct ks_proc;
struct ks_rule;
struct ks_uiclient;

/* Upstream's client timeouts. */
#define KS_UI_POLL_INTERVAL_NS     (1000000000LL)
#define KS_UI_PING_TIMEOUT_NS      (1000000000LL)
#define KS_UI_ASK_TIMEOUT_NS       (120LL * 1000000000)
#define KS_UI_SUBSCRIBE_TIMEOUT_NS (10LL * 1000000000)
#define KS_UI_ALERT_TIMEOUT_NS     (1000000000LL)
/* TCP keepalive (keepalive.ClientParameters in openSocket()). */
#define KS_UI_KEEPALIVE_TIME_NS    (5LL * 1000000000)
#define KS_UI_KEEPALIVE_TIMEOUT_NS (22LL * 1000000000)
/* alertsDispatcher(): alerts kept while the UI is away. */
#define KS_UI_MAX_QUEUED_ALERTS 32

struct ks_uiclient_deps {
    struct ks_evloop *loop;
    struct ks_loader *rules;
    struct ks_stats *stats;
    struct ks_fw *fw; /* NULL: no firewall (tests) */
};

/* NewClient(): loads `config_file` (default path if NULL or ""), applies
 * it (reloadConfiguration: logging, rules, process monitor, firewall...)
 * and watches it for changes. `socket_path` (the -ui-socket flag) wins
 * over the configured Server.Address if not empty. NULL on OOM. */
struct ks_uiclient *ks_uiclient_new(const struct ks_uiclient_deps *deps,
                                    const char *socket_path, const char *config_file);
/* Close() and free: disconnects; a pending question gets a NULL rule. */
void ks_uiclient_free(struct ks_uiclient *c);

/* Connect(): starts the connection poller (once a second). */
void ks_uiclient_connect(struct ks_uiclient *c);

/* Connected(): the gRPC connection is up. */
bool ks_uiclient_connected(const struct ks_uiclient *c);
bool ks_uiclient_is_asking(const struct ks_uiclient *c);
/* DefaultAction(): the UI's DefaultAction while connected (deny until it
 * says otherwise), the configured one while not. */
const char *ks_uiclient_default_action(const struct ks_uiclient *c);
bool ks_uiclient_intercept_unknown(const struct ks_uiclient *c);
/* The configuration in use (c.config). */
const struct ks_config *ks_uiclient_config(const struct ks_uiclient *c);

/* Ask(): sends the connection to the UI. `cb` runs once, later, with the
 * rule the UI answered (owned by the callee; uncompiled) or NULL on any
 * error or timeout. Sets the "asking" flag until `cb` returns. Returns -1
 * (and `cb` never runs) if not connected or already asking. */
typedef void (*ks_ask_cb)(struct ks_rule *rule, void *data);
int ks_uiclient_ask(struct ks_uiclient *c, const struct ks_conn *con,
                    const struct ks_proc *proc, ks_ask_cb cb, void *data);

/* PostAlert() with a text payload, and the Send*Alert() shortcuts. */
void ks_uiclient_post_alert(struct ks_uiclient *c, Protocol__Alert__Type type,
                            Protocol__Alert__What what, Protocol__Alert__Action action,
                            Protocol__Alert__Priority prio, const char *text);
void ks_uiclient_send_info_alert(struct ks_uiclient *c, const char *text);
void ks_uiclient_send_warning_alert(struct ks_uiclient *c, const char *text);
void ks_uiclient_send_error_alert(struct ks_uiclient *c, const char *text);

/* loadDiskConfiguration(true), as when the file changes. For tests. */
void ks_uiclient_reload_from_disk(struct ks_uiclient *c);

#endif
