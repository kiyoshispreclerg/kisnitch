/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The rules editor dialog: port of upstream
 * ui/opensnitch/dialogs/ruleseditor.py and res/ruleseditor.ui. GTK 2. The
 * rule it builds comes from ui/rulegen.c.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_ruleed owns its widgets (destroyed with the window)
 * and its form; the service is borrowed.
 */
#ifndef KS_UI_RULES_EDITOR_H
#define KS_UI_RULES_EDITOR_H

#include <gtk/gtk.h>
#include <stdbool.h>

#include "ui/service.h"

struct ks_ruleed;

/* `on_saved` runs after a rule was saved (Rules.updated). */
struct ks_ruleed *ks_ruleed_new(struct ks_service *svc, GtkWindow *parent,
                                void (*on_saved)(void *), void *ud);
void ks_ruleed_free(struct ks_ruleed *d);

/* The dialog's window (for tests). */
GtkWidget *ks_ruleed_window(struct ks_ruleed *d);

/* new_rule() */
void ks_ruleed_new_rule(struct ks_ruleed *d);
/* new_rule_from_connection(): the event of `time`. False (and no dialog)
 * if there's no such event. */
bool ks_ruleed_new_rule_from_connection(struct ks_ruleed *d, const char *time);
/* edit_rule(records, addr): the rule `name` of `node`, from the rules table. */
void ks_ruleed_edit_rule(struct ks_ruleed *d, const char *node, const char *name);

#endif
