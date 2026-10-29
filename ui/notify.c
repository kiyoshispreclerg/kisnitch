/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/notifications.py. See notify.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/notify.h"

#include <gtk/gtk.h>
#include <string.h>

#include "common/log.h"
#include "ui/service.h"

#ifdef KS_HAVE_NOTIFY
#include <libnotify/notify.h>

#define ACTION_ID_OPEN "action-open"
#define CATEGORY_NETWORK "network"

static bool available, actions;

void ks_notify_init(void)
{
    if (available)
        return;
    if (!notify_init("kisnitch")) {
        ks_warning("[notifications] desktop notifications not available");
        return;
    }
    available = true;
    /* e.g. actions, action-icons, body, body-markup, icon-static, persistence */
    GList *caps = notify_get_server_caps();
    actions = false;
    for (GList *l = caps; l != NULL; l = l->next)
        actions = actions || strcmp(l->data, "actions") == 0;
    if (!actions)
        ks_info("[notifications] the notification daemon doesn't support actions");
    g_list_free_full(caps, g_free);
}

void ks_notify_uninit(void)
{
    if (available)
        notify_uninit();
    available = false;
}

bool ks_notify_available(void)
{
    return available;
}

bool ks_notify_supports_actions(void)
{
    return available && actions;
}

struct open_cb {
    void (*cb)(void *);
    void *ud;
};

static void on_action(NotifyNotification *n, char *action, gpointer data)
{
    (void)n;
    const struct open_cb *o = data;
    if (strcmp(action, ACTION_ID_OPEN) == 0 && o->cb != NULL)
        o->cb(o->ud);
}

static void on_closed(NotifyNotification *n, gpointer data)
{
    (void)data;
    g_object_unref(n);
}

bool ks_notify_show(const char *title, const char *body, int urgency, void (*open_cb)(void *),
                    void *ud)
{
    if (!available)
        return false;
    /* our icon if the theme has it, as upstream shows its own */
    const char *icon = gdk_screen_get_default() != NULL &&
                               gtk_icon_theme_has_icon(gtk_icon_theme_get_default(), "kisnitch")
                           ? "kisnitch"
                           : "dialog-information";
    NotifyNotification *n = notify_notification_new(title, body, icon);
    notify_notification_set_urgency(n, urgency == KS_URGENCY_LOW        ? NOTIFY_URGENCY_LOW
                                       : urgency == KS_URGENCY_CRITICAL ? NOTIFY_URGENCY_CRITICAL
                                                                        : NOTIFY_URGENCY_NORMAL);
    notify_notification_set_category(n, CATEGORY_NETWORK);
    if (actions && open_cb != NULL) {
        struct open_cb *o = g_new(struct open_cb, 1);
        o->cb = open_cb;
        o->ud = ud;
        notify_notification_add_action(n, ACTION_ID_OPEN, "Open", on_action, o, g_free);
    }
    g_signal_connect(n, "closed", G_CALLBACK(on_closed), NULL);
    GError *err = NULL;
    if (!notify_notification_show(n, &err)) {
        ks_warning("[notifications] show() exception: %s", err ? err->message : "");
        g_clear_error(&err);
        g_object_unref(n);
        return false;
    }
    return true;
}

#else

void ks_notify_init(void)
{
}

void ks_notify_uninit(void)
{
}

bool ks_notify_available(void)
{
    return false;
}

bool ks_notify_supports_actions(void)
{
    return false;
}

bool ks_notify_show(const char *title, const char *body, int urgency, void (*open_cb)(void *),
                    void *ud)
{
    (void)title;
    (void)body;
    (void)urgency;
    (void)open_cb;
    (void)ud;
    return false;
}

#endif
