/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The Netstat tab's data: what the daemon's "sockets-monitor" task reports
 * (JSON of daemon/tasks/socketsmonitor) goes to the `sockets` table, as
 * StatsDialog._update_netstat_table() of upstream
 * ui/opensnitch/dialogs/stats.py does; and the names of the numbers
 * (ui/opensnitch/utils/sockets.py).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: nothing is kept; the names returned are literals.
 */
#ifndef KS_UI_NETSTAT_H
#define KS_UI_NETSTAT_H

#include <stddef.h>

#include "ui/db.h"

/* sockets.State / Proto / Family: the name of a number given as text, NULL
 * if it has none (upstream shows an empty cell then). */
const char *ks_sockets_state(const char *n);
const char *ks_sockets_proto(const char *n);
const char *ks_sockets_family(const char *n);

/* The display of a cell of the netstat table: columns 2 (state), 7
 * (protocol) and 10 (family) are names. Returns the text to show. */
const char *ks_netstat_display(int col, const char *text);

/* Empties the `sockets` table and stores the sockets of `json` for `node`.
 * Returns how many, or -1 with a message in `err`. */
int ks_netstat_update(struct ks_db *db, const char *node, const char *json, char *err,
                      size_t errlen);

#endif
