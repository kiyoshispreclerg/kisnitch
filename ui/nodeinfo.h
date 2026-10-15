/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The node panel of the statistics window: what the "node-monitor" task
 * reports (the daemon's sysinfo as JSON) and how upstream's
 * StatsDialog._update_node_info() shows it, quirks included.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: plain structs, no ownership.
 */
#ifndef KS_UI_NODEINFO_H
#define KS_UI_NODEINFO_H

#include <stdbool.h>
#include <stddef.h>

struct ks_nodeinfo {
    /* Pango markup: upstream's <strong> is <b> here */
    char ram[96], swap[96], procs[64], loadavg[160], uptime[96];
    /* QProgressBar value/maximum, as upstream computes them (maximum is 1
     * when the value is 0, to avoid the "busy" effect) */
    int ram_value, ram_max, swap_value, swap_max;
};

/* _update_node_info(): false if `json` isn't the sysinfo. */
bool ks_nodeinfo_parse(const char *json, struct ks_nodeinfo *out);

/* bytes2units() of _update_node_info(): "{0:.0f} {unit}" */
void ks_nodeinfo_bytes(double value, char *buf, size_t len);
/* formatUptime(), with its markup */
void ks_nodeinfo_uptime(double uptime, char *buf, size_t len);

#endif
