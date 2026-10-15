/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The statistics window ("main window"): port of upstream
 * ui/opensnitch/dialogs/stats.py and res/stats.ui, tab by tab. GTK 2.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_stats_win owns its widgets (destroyed with the window)
 * and its models; the service and settings are borrowed.
 */
#ifndef KS_UI_STATS_WIN_H
#define KS_UI_STATS_WIN_H

#include <stdbool.h>

#include "common/pb/ui.pb-c.h"
#include "ui/service.h"
#include "ui/settings.h"

struct ks_stats_win;

struct ks_desktop;
struct ks_stats_win *ks_stats_win_new(struct ks_service *svc, struct ks_settings *settings,
                                      struct ks_desktop *desktop);
void ks_stats_win_free(struct ks_stats_win *w);
/* StatsDialog.show(): shows (or raises) it and refreshes the active tab. */
void ks_stats_win_show(struct ks_stats_win *w);
/* A Ping arrived (StatsDialog.update()): `refresh` is main || details.
 * `st` may be NULL (a node left). */
void ks_stats_win_update(struct ks_stats_win *w, const Protocol__Statistics *st, bool refresh);
/* The connection or interception state changed (update_status()). */
void ks_stats_win_status_changed(struct ks_stats_win *w);

#endif
