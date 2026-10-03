/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Process exec/exit events from the kernel's process events connector
 * (netlink NETLINK_CONNECTOR, CN_IDX_PROC). Port of upstream
 * daemon/netlink/procmon/procmon.go. Needs CAP_NET_ADMIN and a kernel with
 * CONFIG_CONNECTOR and CONFIG_PROC_EVENTS.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#ifndef KS_DAEMON_PROCMON_EVENTS_H
#define KS_DAEMON_PROCMON_EVENTS_H

#include <stdbool.h>
#include <stddef.h>

struct ks_evloop;

/* Subscribes and dispatches events to ks_procmon_on_exec/on_exit from
 * `loop`. -1 if the kernel refuses (e.g. not root). */
int ks_proc_events_start(struct ks_evloop *loop);
void ks_proc_events_stop(void);
bool ks_proc_events_running(void);

/* Parses one datagram from the connector and dispatches its events (for
 * tests and fuzzing). Returns the number of exec/exit events seen. */
int ks_proc_events_handle(const void *buf, size_t len);

#endif
