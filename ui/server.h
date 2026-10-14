/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The UI's gRPC server on the GLib main loop (g_unix_fd_add, no threads):
 * listens where the upstream UI does (ui/bin/opensnitch-ui: --socket or
 * global/server_address, unix:///tmp/osui.sock by default), with the same
 * options (keepalive pings every 5 s, 20 s to answer; message size limit),
 * and hands every call to ui/service.c.
 *
 * Addresses, as grpc's naming: "unix:<path>" ("unix:///tmp/osui.sock" is
 * /tmp/osui.sock), "unix-abstract:<name>", "unix:@<name>" (turned into
 * unix-abstract, as upstream does) and "host:port" / "[addr]:port" for TCP.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_ui_server owns its listening sockets, connections and
 * GLib sources; the service is borrowed and must outlive it (free the
 * server first: closing the connections ends their calls).
 */
#ifndef KS_UI_SERVER_H
#define KS_UI_SERVER_H

#include <stddef.h>

#include "ui/service.h"

struct ks_ui_server;

struct ks_ui_server_opts {
    const char *address;
    size_t max_msg;  /* 0: 4 MiB */
    int max_clients; /* 0: no limit (grpc.max_allowed_incoming_connections) */
};

/* NULL with `err` filled if the address can't be listened on. */
struct ks_ui_server *ks_ui_server_new(const struct ks_ui_server_opts *opts,
                                      struct ks_service *svc, char *err, size_t errlen);
void ks_ui_server_free(struct ks_ui_server *srv);

/* Connections open right now. */
size_t ks_ui_server_conns(const struct ks_ui_server *srv);

/* Config.getMaxMsgLength(): "4MiB", "8MiB", "16MiB" (anything else: 4MiB). */
size_t ks_ui_max_msg_length(const char *setting);

#endif
