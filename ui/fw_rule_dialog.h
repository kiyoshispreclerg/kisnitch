/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall rule dialog: port of upstream
 * ui/opensnitch/dialogs/firewall_rule.py and res/firewall_rule.ui. GTK 2.
 * The form <-> rule logic is in ui/fwrules.c.
 *
 * Qt's QToolBox (one page per condition) becomes a column of expanders,
 * one open at a time; the open one is the "current" condition.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_fwrule_dlg owns its widgets (destroyed with the window)
 * and its list of services; the service is borrowed.
 */
#ifndef KS_UI_FW_RULE_DIALOG_H
#define KS_UI_FW_RULE_DIALOG_H

#include <gtk/gtk.h>

#include "ui/service.h"

struct ks_fwrule_dlg;

/* `on_changed` runs when the rules of a node changed (rulesUpdated). */
struct ks_fwrule_dlg *ks_fwrule_dlg_new(struct ks_service *svc, GtkWindow *parent,
                                        void (*on_changed)(void *), void *ud);
void ks_fwrule_dlg_free(struct ks_fwrule_dlg *d);
GtkWidget *ks_fwrule_dlg_window(struct ks_fwrule_dlg *d);

/* new() */
void ks_fwrule_dlg_new_rule(struct ks_fwrule_dlg *d);
/* load(addr, uuid) */
void ks_fwrule_dlg_load(struct ks_fwrule_dlg *d, const char *addr, const char *uuid);
/* exclude_service(direction): KS_FWF_IN or KS_FWF_OUT */
void ks_fwrule_dlg_exclude_service(struct ks_fwrule_dlg *d, int direction);

#endif
