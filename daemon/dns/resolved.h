/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * systemd-resolved monitor: passively reads the answers systemd-resolved
 * gives out (including the ones served from its cache, which never cross
 * the netfilter queue) and tracks them in daemon/dns/cache.c. Port of
 * upstream daemon/dns/systemd/monitor.go and initSystemdResolvedMonitor()
 * in daemon/main.go.
 *
 * Optional, as upstream: nothing happens unless resolved's monitor socket
 * exists when the daemon starts. Systems without systemd-resolved (Devuan,
 * plain resolv.conf, dnsmasq, unbound...) rely on the queue alone. There
 * is no libsystemd dependency: varlink is JSON messages ending in a NUL
 * byte over a Unix socket, spoken directly on the event loop.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_resolved owns its socket, buffer and timer; it borrows
 * the event loop, which must outlive it.
 */
#ifndef KS_DAEMON_DNS_RESOLVED_H
#define KS_DAEMON_DNS_RESOLVED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ks_evloop;
struct ks_resolved;

/* socketPath */
#define KS_RESOLVED_SOCKET "/run/systemd/resolve/io.systemd.Resolve.Monitor"
/* connPoller's interval */
#define KS_RESOLVED_RECONNECT_NS (5 * 1000000000LL)
/* Longest varlink message accepted (Go's reader has no limit). */
#define KS_RESOLVED_MSG_MAX (4u << 20)

/* initSystemdResolvedMonitor(): connects to `socket_path` (normally
 * KS_RESOLVED_SOCKET) and subscribes to query results. Returns NULL, after
 * a debug message, if the socket doesn't exist or the first connection or
 * subscription fails; upstream doesn't retry then either. */
struct ks_resolved *ks_resolved_start(struct ks_evloop *loop, const char *socket_path);

/* Closes the connection and cancels any pending reconnection. NULL is
 * accepted. */
void ks_resolved_stop(struct ks_resolved *r);

/* True while subscribed. */
bool ks_resolved_connected(const struct ks_resolved *r);

/* What one varlink reply means for the subscription. */
enum ks_resolved_reply {
    KS_RESOLVED_CONTINUE, /* "continues": more replies follow */
    KS_RESOLVED_END,      /* last reply: monitor() exits */
    KS_RESOLVED_ERROR,    /* invalid reply or varlink error */
};

/* Handles one reply (without its NUL): the varlink receive() callback plus
 * the response handling of initSystemdResolvedMonitor(). Exposed for tests
 * and fuzzing. */
enum ks_resolved_reply ks_resolved_handle_reply(const char *msg, size_t len);

#endif
