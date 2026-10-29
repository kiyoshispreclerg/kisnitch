/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall rules table of the statistics window (stats_fw.c)
 * and its firewall dialog.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_sw_fw owns its store and the firewall dialog (made on
 * first use); its widget belongs to the window it's packed in.
 */
#ifndef KS_UI_STATS_FW_H
#define KS_UI_STATS_FW_H

#include <gtk/gtk.h>
#include <stdbool.h>

#include "ui/stats_win_priv.h"

struct ks_sw_fw;
struct ks_fw_dlg;

struct ks_sw_fw *ks_sw_fw_new(struct ks_stats_win *w);
void ks_sw_fw_free(struct ks_sw_fw *f);
/* the view, hidden until the "Firewall" entry of the rules combo is chosen */
GtkWidget *ks_sw_fw_widget(struct ks_sw_fw *f);
bool ks_sw_fw_visible(struct ks_sw_fw *f);
/* the rules of every node, filtered by the window's filter text */
void ks_sw_fw_refresh(struct ks_sw_fw *f);
/* the firewall dialog (fwButton), made on first use */
struct ks_fw_dlg *ks_sw_fw_dialog(struct ks_sw_fw *f);
/* a node subscribed or went away */
void ks_sw_fw_nodes_updated(struct ks_sw_fw *f);

#endif
