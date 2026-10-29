/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall dialog: port of upstream
 * ui/opensnitch/dialogs/firewall.py and res/firewall.ui. GTK 2. Inbound and
 * outbound policies (applied as the profiles of ui/fwrules.c), enabling the
 * firewall, and the buttons opening the rule dialog.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_fw_dlg owns its widgets and the rule dialog; the
 * service is borrowed.
 */
#ifndef KS_UI_FW_DIALOG_H
#define KS_UI_FW_DIALOG_H

#include <gtk/gtk.h>

#include "ui/fw_rule_dialog.h"
#include "ui/service.h"

struct ks_fw_dlg;

/* `on_changed` runs when a node's firewall configuration changed. */
struct ks_fw_dlg *ks_fw_dlg_new(struct ks_service *svc, GtkWindow *parent,
                                void (*on_changed)(void *), void *ud);
void ks_fw_dlg_free(struct ks_fw_dlg *d);
GtkWidget *ks_fw_dlg_window(struct ks_fw_dlg *d);
/* show() */
void ks_fw_dlg_show(struct ks_fw_dlg *d);
/* load_rule(addr, uuid): the rule dialog for that rule */
void ks_fw_dlg_load_rule(struct ks_fw_dlg *d, const char *addr, const char *uuid);
/* _cb_nodes_updated(total) */
void ks_fw_dlg_nodes_updated(struct ks_fw_dlg *d);
struct ks_fwrule_dlg *ks_fw_dlg_rule_dialog(struct ks_fw_dlg *d);

#endif
