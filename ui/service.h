/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI side of the protocol: port of upstream ui/opensnitch/service.py
 * (UIService). Serves the RPCs of proto/ui.proto for the gRPC server
 * (ui/server.c), keeps the nodes and their rules, queues the questions
 * (AskRule) for the pop-up one at a time, and tracks the state the tray
 * shows (connected, interception enabled).
 *
 * No widgets here: the GTK side (or a test) plugs in through struct
 * ks_service_ops. Everything runs on the GLib main loop.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_service owns the nodes, the rules table, the network
 * aliases and the pending questions; the settings are borrowed. A struct
 * ks_ask given to ops->prompt stays valid until ks_service_answer() is
 * called with it.
 */
#ifndef KS_UI_SERVICE_H
#define KS_UI_SERVICE_H

#include <stdbool.h>
#include <stddef.h>

#include "common/grpc/grpc.h"
#include "common/pb/ui.pb-c.h"
#include "ui/nodes.h"
#include "ui/prompt_rule.h"
#include "ui/rulesdb.h"
#include "ui/settings.h"

struct ks_service;

/* A question from a daemon. */
struct ks_ask {
    struct ks_service *svc;
    struct ks_grpc_call *call; /* NULL once the daemon gave up */
    Protocol__Connection *con;
    char peer[KS_NODE_ADDR_MAX]; /* the gRPC peer ("unix:") */
    char node[KS_NODE_ADDR_MAX]; /* "unix:/local" */
    bool is_local;
    struct ks_ask *next;
    void *ctx; /* the call's context (internal) */
};

struct ks_service_ops {
    /* Show the pop-up for `ask`; it must end with ks_service_answer(). */
    void (*prompt)(void *ud, struct ks_ask *ask);
    /* The connection or interception state changed (see the getters). */
    void (*status_changed)(void *ud);
    /* A message for the tray / desktop notifications. */
    void (*message)(void *ud, const char *title, const char *body);
    /* The daemon's version differs from ours (once). */
    void (*version_warning)(void *ud, const char *daemon_version, const char *ui_version);
    /* A Ping's statistics were stored (_on_update_stats); `refresh` says
     * the events or counters changed. NULL stats: a node left. */
    void (*stats_updated)(void *ud, const Protocol__Statistics *stats, bool refresh);
};

struct ks_service_state {
    bool connected;
    bool fw_enabled;
    bool fw_menu_enabled; /* the tray's enable/disable entry */
};

struct ks_service *ks_service_new(struct ks_settings *settings, const struct ks_service_ops *ops,
                                  void *ud);
void ks_service_free(struct ks_service *svc);
/* The UI database (owned by the service); NULL only if creation failed. */
struct ks_db *ks_service_db(struct ks_service *svc);

/* The gRPC server's on_call: sets up the call for `path` coming from
 * `peer` ("unix:", "ipv4:127.0.0.1:4321"). 0 or a status to reject it. */
int ks_service_on_call(struct ks_service *svc, struct ks_grpc_call *call, const char *path,
                       const char *peer);

/* The pop-up's answer: `rule` (NULL: no rule, the daemon gets an error and
 * applies its default action) and whether the countdown ran out. Frees
 * `ask` and moves to the next question. */
void ks_service_answer(struct ks_service *svc, struct ks_ask *ask, Protocol__Rule *rule,
                       bool timeout_triggered);

/* The tray's "Enable"/"Disable": _enable_interception(). */
void ks_service_toggle_interception(struct ks_service *svc);

/* Nodes.delete() from the statistics window: ends the node's Notifications
 * stream (the daemon reconnects, if it is still there). */
void ks_service_node_delete(struct ks_service *svc, const char *addr);

/* Service._on_settings_saved(): the database cleaner follows the settings
 * (started, restarted or stopped). */
void ks_service_settings_saved(struct ks_service *svc);

/* Stop accepting nodes (_on_close: exit mark). */
void ks_service_closing(struct ks_service *svc);

struct ks_service_state ks_service_state(const struct ks_service *svc);
struct ks_nodes *ks_service_nodes(struct ks_service *svc);
struct ks_rulesdb *ks_service_rules(struct ks_service *svc);
const struct ks_py_aliases *ks_service_aliases(const struct ks_service *svc);
struct ks_settings *ks_service_settings(struct ks_service *svc);

/* duration.to_seconds() of the UI: sums every "<n><unit>" with s, m, h,
 * d and w (a day of 60 hours, a week of 60 days, as upstream). */
long ks_ui_duration_seconds(const char *d);

/* Utils.check_versions(): true if major or minor differ. */
bool ks_ui_versions_differ(const char *ui_version, const char *daemon_version);

#endif
