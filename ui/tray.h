/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The tray icon and its menu: port of the tray part of upstream
 * ui/opensnitch/service.py (_setup_tray, _setup_icons, the status
 * changes) and of the Autostart class of ui/opensnitch/utils/xdg.py.
 *
 * Icons (ui/res/): off (no daemon), white (connected, interception on),
 * pause (connected, interception off), alert (a rule was applied by the
 * pop-up's timeout).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_tray owns its status icon, menu and pixbufs; the
 * service is borrowed.
 */
#ifndef KS_UI_TRAY_H
#define KS_UI_TRAY_H

#include <stdbool.h>

#include "ui/service.h"

struct ks_tray;

/* `on_close` runs for the menu's "Close". */
struct ks_tray *ks_tray_new(struct ks_service *svc, void (*on_close)(void *), void *ud);
void ks_tray_free(struct ks_tray *t);

/* Updates the icon and the menu from the service state. */
void ks_tray_update(struct ks_tray *t);
/* The service state changed: new icon (which also clears the alert, as
 * upstream's setIcon() calls do). */
void ks_tray_status_changed(struct ks_tray *t);
/* A message to show: the icon turns to "alert". */
void ks_tray_alert(struct ks_tray *t);
bool ks_tray_available(struct ks_tray *t);

/* utils/xdg.py Autostart, for opensnitch_ui.desktop (the file the
 * upstream UI installs; ours uses the same name so both agree on it). */
bool ks_autostart_enabled(const char *config_home);
int ks_autostart_enable(const char *config_home, bool on);

#endif
