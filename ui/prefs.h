/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The preferences dialog: port of upstream
 * ui/opensnitch/dialogs/preferences.py and res/preferences.ui (pop-ups, UI,
 * rules, nodes and database). GTK 2. The configuration of a node comes
 * from ui/prefs_node.c.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_prefs owns its widgets (destroyed with the window)
 * and its form; the service and settings are borrowed.
 */
#ifndef KS_UI_PREFS_H
#define KS_UI_PREFS_H

#include <gtk/gtk.h>

#include "ui/service.h"
#include "ui/settings.h"

struct ks_prefs;

/* `on_saved` runs after the settings were saved (the `saved` signal). */
struct ks_prefs *ks_prefs_new(struct ks_service *svc, struct ks_settings *settings,
                              GtkWindow *parent, void (*on_saved)(void *), void *ud);
void ks_prefs_free(struct ks_prefs *p);
/* show() */
void ks_prefs_show(struct ks_prefs *p);
/* show_node_prefs(addr): the Nodes tab, on that node */
void ks_prefs_show_node(struct ks_prefs *p, const char *addr);
/* The dialog's window (for tests). */
GtkWidget *ks_prefs_window(struct ks_prefs *p);

#endif
