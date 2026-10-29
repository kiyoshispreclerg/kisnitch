/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Desktop notifications through the notification daemon (D-Bus), with
 * libnotify when built with NOTIFY=1. Port of upstream
 * ui/opensnitch/notifications.py (DesktopNotifications, with notify2).
 * Without NOTIFY=1 they're never available, and messages only turn the
 * tray icon to "alert".
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the shown notifications are freed when the daemon closes them.
 */
#ifndef KS_UI_NOTIFY_H
#define KS_UI_NOTIFY_H

#include <stdbool.h>

/* config.NOTIFICATION_TYPE_*: "notifications/type" */
#define KS_NOTIFICATION_TYPE_SYSTEM 0
#define KS_NOTIFICATION_TYPE_QT 1 /* here: the tray icon's alert */

/* __init__: connects to the notification daemon. */
void ks_notify_init(void);
void ks_notify_uninit(void);
/* is_available() */
bool ks_notify_available(void);
/* support_actions(): the daemon shows buttons */
bool ks_notify_supports_actions(void);

/* show(): `urgency` is KS_URGENCY_* (ui/service.h). With `open_cb` (and
 * a daemon that supports actions) the notification has an "Open" button.
 * false if it couldn't be shown. */
bool ks_notify_show(const char *title, const char *body, int urgency, void (*open_cb)(void *),
                    void *ud);

#endif
