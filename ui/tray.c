/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the tray of upstream ui/opensnitch/service.py and of
 * ui/opensnitch/utils/xdg.py (Autostart).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/tray.h"

#include <errno.h>
#include <gtk/gtk.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "ui/res.h"

#define HELP_CONFIG_URL "https://github.com/evilsocket/opensnitch/wiki/Configurations"
#define ICON_PX 64
#define DESKTOP_FILE "opensnitch_ui.desktop"
#define SYSTEM_DESKTOP "/usr/share/applications/" DESKTOP_FILE
#define SYSTEM_AUTOSTART "/etc/xdg/autostart/" DESKTOP_FILE

enum { ICON_OFF, ICON_WHITE, ICON_PAUSE, ICON_ALERT, NICONS };

struct ks_tray {
    struct ks_service *svc;
    void (*on_close)(void *);
    void *ud;
    GtkStatusIcon *icon;
    GdkPixbuf *pix[NICONS];
    GtkWidget *menu, *fw_item, *autostart_item, *stats_item;
    bool alert;
    bool filling;
};

/* ---- autostart --------------------------------------------------------- */

static void user_autostart(const char *config_home, char *buf, size_t len)
{
    snprintf(buf, len, "%s/autostart/" DESKTOP_FILE, config_home);
}

static const char *system_autostart(void)
{
    if (access(SYSTEM_AUTOSTART, F_OK) != 0 && access("/usr" SYSTEM_AUTOSTART, F_OK) == 0)
        return "/usr" SYSTEM_AUTOSTART;
    return SYSTEM_AUTOSTART;
}

static bool is_file(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

bool ks_autostart_enabled(const char *config_home)
{
    char user[PATH_MAX];
    user_autostart(config_home, user, sizeof(user));
    if (is_file(user)) {
        char err[128];
        size_t len;
        char *text = ks_read_file(user, 1024 * 1024, &len, err, sizeof(err));
        bool hidden = false;
        /* re.search("^Hidden=true", line, re.IGNORECASE) on each line */
        for (char *l = text; l != NULL && *l;) {
            if (strncasecmp(l, "Hidden=true", 11) == 0)
                hidden = true;
            char *nl = strchr(l, '\n');
            l = nl ? nl + 1 : NULL;
        }
        free(text);
        return !hidden;
    }
    return is_file(system_autostart());
}

static int copy_file(const char *src, const char *dst, const char *append)
{
    char err[256];
    size_t len;
    char *text = ks_read_file(src, 1024 * 1024, &len, err, sizeof(err));
    if (text == NULL)
        return -1;
    size_t al = append ? strlen(append) : 0;
    char *all = realloc(text, len + al + 1);
    if (all == NULL) {
        free(text);
        return -1;
    }
    if (append)
        memcpy(all + len, append, al + 1);
    int rc = ks_write_file(dst, all, len + al, 0644, err, sizeof(err));
    free(all);
    return rc;
}

int ks_autostart_enable(const char *config_home, bool on)
{
    char user[PATH_MAX], dir[PATH_MAX];
    user_autostart(config_home, user, sizeof(user));
    /* createUserDir() */
    mkdir(config_home, 0700);
    snprintf(dir, sizeof(dir), "%s/autostart", config_home);
    if (mkdir(dir, 0755) < 0 && errno != EEXIST)
        return -1;
    const char *sys = system_autostart();
    if (on) {
        if (is_file(sys) && is_file(user))
            return unlink(user);
        if (is_file(SYSTEM_DESKTOP))
            return copy_file(SYSTEM_DESKTOP, user, NULL);
        return 0;
    }
    if (is_file(sys))
        return copy_file(sys, user, "Hidden=true\n");
    if (is_file(user))
        return unlink(user);
    return 0;
}

static const char *config_home(void)
{
    static char buf[PATH_MAX];
    const char *x = getenv("XDG_CONFIG_HOME");
    if (x != NULL && x[0] != '\0')
        return x;
    snprintf(buf, sizeof(buf), "%s/.config", g_get_home_dir());
    return buf;
}

/* ---- icons ------------------------------------------------------------- */

static GdkPixbuf *load_png(const unsigned char *data, size_t len)
{
    GdkPixbufLoader *l = gdk_pixbuf_loader_new_with_type("png", NULL);
    if (l == NULL)
        return NULL;
    /* the PNGs are 512x512: decode them small */
    gdk_pixbuf_loader_set_size(l, ICON_PX, ICON_PX);
    GdkPixbuf *pb = NULL;
    if (gdk_pixbuf_loader_write(l, data, len, NULL) && gdk_pixbuf_loader_close(l, NULL)) {
        pb = gdk_pixbuf_loader_get_pixbuf(l);
        if (pb)
            g_object_ref(pb);
    } else {
        gdk_pixbuf_loader_close(l, NULL);
    }
    g_object_unref(l);
    return pb;
}

void ks_tray_update(struct ks_tray *t)
{
    struct ks_service_state st = ks_service_state(t->svc);
    int icon = !st.connected ? ICON_OFF : st.fw_enabled ? ICON_WHITE : ICON_PAUSE;
    if (t->alert && st.connected)
        icon = ICON_ALERT;
    if (t->pix[icon])
        gtk_status_icon_set_from_pixbuf(t->icon, t->pix[icon]);
    gtk_menu_item_set_label(GTK_MENU_ITEM(t->fw_item), st.fw_enabled ? "Disable" : "Enable");
    gtk_widget_set_sensitive(t->fw_item, st.fw_menu_enabled);
    gtk_status_icon_set_tooltip_text(
        t->icon, !st.connected ? "Kisnitch: no daemon connected"
                 : st.fw_enabled ? "Kisnitch: interception enabled"
                                 : "Kisnitch: interception disabled");
}

void ks_tray_status_changed(struct ks_tray *t)
{
    t->alert = false;
    ks_tray_update(t);
}

void ks_tray_alert(struct ks_tray *t)
{
    t->alert = true;
    ks_tray_update(t);
}

bool ks_tray_available(struct ks_tray *t)
{
    return gtk_status_icon_is_embedded(t->icon);
}

/* ---- menu -------------------------------------------------------------- */

static void on_fw(GtkMenuItem *m, gpointer data)
{
    (void)m;
    struct ks_tray *t = data;
    ks_service_toggle_interception(t->svc);
    ks_tray_update(t);
}

static void on_autostart(GtkCheckMenuItem *m, gpointer data)
{
    struct ks_tray *t = data;
    if (t->filling)
        return;
    if (ks_autostart_enable(config_home(), gtk_check_menu_item_get_active(m)) < 0)
        ks_warning("Error switching autostart: %s", strerror(errno));
}

static void on_help(GtkMenuItem *m, gpointer data)
{
    (void)m;
    (void)data;
    GError *err = NULL;
    if (!gtk_show_uri(NULL, HELP_CONFIG_URL, GDK_CURRENT_TIME, &err)) {
        ks_warning("can't open %s: %s", HELP_CONFIG_URL, err ? err->message : "");
        g_clear_error(&err);
    }
}

static void on_close_item(GtkMenuItem *m, gpointer data)
{
    (void)m;
    struct ks_tray *t = data;
    if (t->on_close)
        t->on_close(t->ud);
}

static void on_popup(GtkStatusIcon *icon, guint button, guint time, gpointer data)
{
    struct ks_tray *t = data;
    /* _on_show_menu() */
    t->filling = true;
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(t->autostart_item),
                                   ks_autostart_enabled(config_home()));
    t->filling = false;
    gtk_menu_popup(GTK_MENU(t->menu), NULL, NULL, gtk_status_icon_position_menu, icon, button,
                   time);
}

static void on_activate(GtkStatusIcon *icon, gpointer data)
{
    (void)icon;
    struct ks_tray *t = data;
    /* the main window comes with phase 7; a click clears the alert */
    t->alert = false;
    ks_tray_update(t);
}

struct ks_tray *ks_tray_new(struct ks_service *svc, void (*on_close)(void *), void *ud)
{
    struct ks_tray *t = calloc(1, sizeof(*t));
    if (t == NULL)
        return NULL;
    t->svc = svc;
    t->on_close = on_close;
    t->ud = ud;
    t->pix[ICON_OFF] = load_png(ks_res_icon_off_png, ks_res_icon_off_png_len);
    t->pix[ICON_WHITE] = load_png(ks_res_icon_white_png, ks_res_icon_white_png_len);
    t->pix[ICON_PAUSE] = load_png(ks_res_icon_pause_png, ks_res_icon_pause_png_len);
    t->pix[ICON_ALERT] = load_png(ks_res_icon_alert_png, ks_res_icon_alert_png_len);

    t->icon = gtk_status_icon_new_from_pixbuf(t->pix[ICON_OFF]);
    gtk_status_icon_set_title(t->icon, "Kisnitch");

    t->menu = gtk_menu_new();
    t->stats_item = gtk_menu_item_new_with_label("Open main window");
    gtk_widget_set_sensitive(t->stats_item, FALSE); /* phase 7 */
    t->fw_item = gtk_menu_item_new_with_label("Disable");
    gtk_widget_set_sensitive(t->fw_item, FALSE);
    t->autostart_item = gtk_check_menu_item_new_with_label("Autostart");
    GtkWidget *help = gtk_menu_item_new_with_label("Help");
    GtkWidget *close = gtk_menu_item_new_with_label("Close");
    GtkMenuShell *ms = GTK_MENU_SHELL(t->menu);
    gtk_menu_shell_append(ms, t->stats_item);
    gtk_menu_shell_append(ms, t->fw_item);
    gtk_menu_shell_append(ms, gtk_separator_menu_item_new());
    gtk_menu_shell_append(ms, t->autostart_item);
    gtk_menu_shell_append(ms, gtk_separator_menu_item_new());
    gtk_menu_shell_append(ms, help);
    gtk_menu_shell_append(ms, close);
    gtk_widget_show_all(t->menu);

    g_signal_connect(t->fw_item, "activate", G_CALLBACK(on_fw), t);
    g_signal_connect(t->autostart_item, "toggled", G_CALLBACK(on_autostart), t);
    g_signal_connect(help, "activate", G_CALLBACK(on_help), t);
    g_signal_connect(close, "activate", G_CALLBACK(on_close_item), t);
    g_signal_connect(t->icon, "popup-menu", G_CALLBACK(on_popup), t);
    g_signal_connect(t->icon, "activate", G_CALLBACK(on_activate), t);
    ks_tray_update(t);
    return t;
}

void ks_tray_free(struct ks_tray *t)
{
    if (t == NULL)
        return;
    gtk_widget_destroy(t->menu);
    g_object_unref(t->icon);
    for (int i = 0; i < NICONS; i++) {
        if (t->pix[i])
            g_object_unref(t->pix[i]);
    }
    free(t);
}
