/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The simplified system firewall panel (a Kisnitch feature, see
 * ui/fwsimple.h): default policies and a table of simple rules of a node,
 * with the advanced ones listed and opened in the full rule dialog.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the panel owns its window; the service and the rule dialog are
 * borrowed and must outlive it.
 */
#ifndef KS_UI_FW_SIMPLE_H
#define KS_UI_FW_SIMPLE_H

#include <gtk/gtk.h>

#include "ui/fw_rule_dialog.h"
#include "ui/service.h"

struct ks_fws_dlg;

/* `on_changed` is called after a change was sent to a node. */
struct ks_fws_dlg *ks_fws_dlg_new(struct ks_service *svc, GtkWindow *parent,
                                  struct ks_fwrule_dlg *rule_dlg, void (*on_changed)(void *),
                                  void *ud);
void ks_fws_dlg_free(struct ks_fws_dlg *d);
void ks_fws_dlg_show(struct ks_fws_dlg *d);
/* Reloads the table and the policies (after changes made elsewhere). */
void ks_fws_dlg_refresh(struct ks_fws_dlg *d);
GtkWidget *ks_fws_dlg_window(struct ks_fws_dlg *d);

#endif
