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
#include "ui/i18n.h"

#define HELP_CONFIG_URL "https://github.com/evilsocket/opensnitch/wiki/Configurations"
#define ICON_PX 64
#define DESKTOP_FILE "kisnitch.desktop"
#define SYSTEM_DESKTOP "/usr/share/applications/" DESKTOP_FILE
#define SYSTEM_AUTOSTART "/etc/xdg/autostart/" DESKTOP_FILE

enum { ICON_OFF, ICON_WHITE, ICON_PAUSE, ICON_ALERT, NICONS };

struct ks_tray {
    struct ks_service *svc;
    void (*on_open)(void *);
    void (*on_close)(void *);
    void *ud;
    GtkStatusIcon *icon;
    GdkPixbuf *pix[NICONS];
    /* StatusNotifierItem (see the sni section) */
    GDBusConnection *bus;
    GDBusNodeInfo *sni_info;
    guint sni_reg, sni_name, sni_watch;
    GDBusNodeInfo *menu_info;
    guint menu_reg, menu_rev;
    char sni_service[96];
    bool sni_ok;   /* a watcher has our item: the XEmbed icon is hidden */
    GtkWidget *menu, *fw_item, *autostart_item, *stats_item;
    int cur;
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

static void sni_changed(struct ks_tray *t);
static void fill_menu(struct ks_tray *t);

static GdkPixbuf *load_png(const unsigned char *data, size_t len)
{
    GdkPixbufLoader *l = gdk_pixbuf_loader_new_with_type("png", NULL);
    if (l == NULL)
        return NULL;
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
    t->cur = icon;
    if (t->pix[icon])
        gtk_status_icon_set_from_pixbuf(t->icon, t->pix[icon]);
    gtk_menu_item_set_label(GTK_MENU_ITEM(t->fw_item), st.fw_enabled ? _("Disable") : _("Enable"));
    gtk_widget_set_sensitive(t->fw_item, st.fw_menu_enabled);
    gtk_status_icon_set_tooltip_text(
        t->icon, !st.connected ? _("Kisnitch: no daemon connected")
                 : st.fw_enabled ? _("Kisnitch: interception enabled")
                                 : _("Kisnitch: interception disabled"));
    sni_changed(t);
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
    return t->sni_ok || gtk_status_icon_is_embedded(t->icon);
}

/* ---- StatusNotifierItem -------------------------------------------------
 * GtkStatusIcon only speaks the XEmbed tray protocol. Panels without it
 * (xispanel, KDE, most Wayland shells, GNOME with the AppIndicator
 * extension) host org.kde.StatusNotifierItem instead, which is what the
 * Qt UI of the upstream uses. The item has no dbusmenu: the menu is our
 * own GtkMenu, popped up by ContextMenu(). While a watcher holds the item,
 * the XEmbed icon is hidden so the two never show together. */

#define SNI_PATH "/StatusNotifierItem"
#define MENU_PATH "/MenuBar"
#define SNI_WATCHER "org.kde.StatusNotifierWatcher"
#define SNI_WATCHER_PATH "/StatusNotifierWatcher"

static const char sni_xml[] =
    "<node><interface name='org.kde.StatusNotifierItem'>"
    "<property name='Category' type='s' access='read'/>"
    "<property name='Id' type='s' access='read'/>"
    "<property name='Title' type='s' access='read'/>"
    "<property name='Status' type='s' access='read'/>"
    "<property name='WindowId' type='i' access='read'/>"
    "<property name='IconName' type='s' access='read'/>"
    "<property name='IconPixmap' type='a(iiay)' access='read'/>"
    "<property name='OverlayIconName' type='s' access='read'/>"
    "<property name='OverlayIconPixmap' type='a(iiay)' access='read'/>"
    "<property name='AttentionIconName' type='s' access='read'/>"
    "<property name='AttentionIconPixmap' type='a(iiay)' access='read'/>"
    "<property name='AttentionMovieName' type='s' access='read'/>"
    "<property name='ToolTip' type='(sa(iiay)ss)' access='read'/>"
    "<property name='ItemIsMenu' type='b' access='read'/>"
    "<property name='Menu' type='o' access='read'/>"
    "<method name='ContextMenu'><arg type='i' name='x' direction='in'/>"
    "<arg type='i' name='y' direction='in'/></method>"
    "<method name='Activate'><arg type='i' name='x' direction='in'/>"
    "<arg type='i' name='y' direction='in'/></method>"
    "<method name='SecondaryActivate'><arg type='i' name='x' direction='in'/>"
    "<arg type='i' name='y' direction='in'/></method>"
    "<method name='Scroll'><arg type='i' name='delta' direction='in'/>"
    "<arg type='s' name='orientation' direction='in'/></method>"
    "<signal name='NewIcon'/><signal name='NewToolTip'/><signal name='NewStatus'>"
    "<arg type='s' name='status'/></signal>"
    "</interface></node>";

/* a(iiay) with one entry: the pixbuf as ARGB32, network byte order */
static GVariant *sni_pixmap(GdkPixbuf *pb)
{
    GVariantBuilder arr;
    g_variant_builder_init(&arr, G_VARIANT_TYPE("a(iiay)"));
    if (pb != NULL) {
        int w = gdk_pixbuf_get_width(pb), h = gdk_pixbuf_get_height(pb);
        int rs = gdk_pixbuf_get_rowstride(pb), n = gdk_pixbuf_get_n_channels(pb);
        bool alpha = gdk_pixbuf_get_has_alpha(pb);
        const guchar *px = gdk_pixbuf_get_pixels(pb);
        guchar *buf = g_malloc((gsize)w * h * 4);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                const guchar *s = px + (gsize)y * rs + (gsize)x * n;
                guchar *d = buf + ((gsize)y * w + x) * 4;
                d[0] = alpha ? s[3] : 0xff;
                d[1] = s[0];
                d[2] = s[1];
                d[3] = s[2];
            }
        }
        GVariant *bytes = g_variant_new_from_data(G_VARIANT_TYPE("ay"), buf, (gsize)w * h * 4,
                                                  TRUE, g_free, buf);
        g_variant_builder_add(&arr, "(ii@ay)", w, h, bytes);
    }
    return g_variant_builder_end(&arr);
}

static const char *sni_tooltip_text(struct ks_tray *t)
{
    struct ks_service_state st = ks_service_state(t->svc);
    return !st.connected ? _("Kisnitch: no daemon connected")
           : st.fw_enabled ? _("Kisnitch: interception enabled")
                           : _("Kisnitch: interception disabled");
}

static GVariant *sni_get(GDBusConnection *c, const gchar *sender, const gchar *path,
                         const gchar *iface, const gchar *prop, GError **err, gpointer data)
{
    (void)c; (void)sender; (void)path; (void)iface; (void)err;
    struct ks_tray *t = data;
    if (!strcmp(prop, "Category"))
        return g_variant_new_string("ApplicationStatus");
    if (!strcmp(prop, "Id"))
        return g_variant_new_string("kisnitch");
    if (!strcmp(prop, "Title"))
        return g_variant_new_string("Kisnitch");
    if (!strcmp(prop, "Status"))
        return g_variant_new_string(t->alert ? "NeedsAttention" : "Active");
    if (!strcmp(prop, "WindowId"))
        return g_variant_new_int32(0);
    if (!strcmp(prop, "IconPixmap"))
        return sni_pixmap(t->pix[t->cur]);
    if (!strcmp(prop, "OverlayIconPixmap") || !strcmp(prop, "AttentionIconPixmap"))
        return sni_pixmap(NULL);
    if (!strcmp(prop, "IconName") || !strcmp(prop, "OverlayIconName") ||
        !strcmp(prop, "AttentionIconName") || !strcmp(prop, "AttentionMovieName"))
        return g_variant_new_string("");
    if (!strcmp(prop, "ToolTip"))
        return g_variant_new("(s@a(iiay)ss)", "", sni_pixmap(NULL), sni_tooltip_text(t), "");
    if (!strcmp(prop, "ItemIsMenu"))
        return g_variant_new_boolean(FALSE);
    if (!strcmp(prop, "Menu"))
        return g_variant_new_object_path(MENU_PATH);
    return NULL;
}

static void show_menu(struct ks_tray *t, guint button, guint32 time);
static void do_activate(struct ks_tray *t);

static void sni_call(GDBusConnection *c, const gchar *sender, const gchar *path,
                     const gchar *iface, const gchar *method, GVariant *params,
                     GDBusMethodInvocation *inv, gpointer data)
{
    (void)c; (void)sender; (void)path; (void)iface; (void)params;
    struct ks_tray *t = data;
    if (!strcmp(method, "ContextMenu"))
        show_menu(t, 3, gtk_get_current_event_time());
    else if (!strcmp(method, "Activate"))
        do_activate(t);
    g_dbus_method_invocation_return_value(inv, NULL);
}

/* com.canonical.dbusmenu over the GtkMenu: the panels that draw the menu
 * themselves (xispanel, KDE) never call ContextMenu(), they read "Menu" and
 * ask for the layout. Item ids are the children's position + 1; the menu is
 * flat, so the layout always comes whole, whatever the depth asked. */

static const char menu_xml[] =
    "<node><interface name='com.canonical.dbusmenu'>"
    "<property name='Version' type='u' access='read'/>"
    "<property name='TextDirection' type='s' access='read'/>"
    "<property name='Status' type='s' access='read'/>"
    "<property name='IconThemePath' type='as' access='read'/>"
    "<method name='GetLayout'><arg type='i' name='parentId' direction='in'/>"
    "<arg type='i' name='recursionDepth' direction='in'/>"
    "<arg type='as' name='propertyNames' direction='in'/>"
    "<arg type='u' name='revision' direction='out'/>"
    "<arg type='(ia{sv}av)' name='layout' direction='out'/></method>"
    "<method name='GetGroupProperties'><arg type='ai' name='ids' direction='in'/>"
    "<arg type='as' name='propertyNames' direction='in'/>"
    "<arg type='a(ia{sv})' name='properties' direction='out'/></method>"
    "<method name='GetProperty'><arg type='i' name='id' direction='in'/>"
    "<arg type='s' name='name' direction='in'/>"
    "<arg type='v' name='value' direction='out'/></method>"
    "<method name='Event'><arg type='i' name='id' direction='in'/>"
    "<arg type='s' name='eventId' direction='in'/><arg type='v' name='data' direction='in'/>"
    "<arg type='u' name='timestamp' direction='in'/></method>"
    "<method name='EventGroup'><arg type='a(isvu)' name='events' direction='in'/>"
    "<arg type='ai' name='idErrors' direction='out'/></method>"
    "<method name='AboutToShow'><arg type='i' name='id' direction='in'/>"
    "<arg type='b' name='needUpdate' direction='out'/></method>"
    "<method name='AboutToShowGroup'><arg type='ai' name='ids' direction='in'/>"
    "<arg type='ai' name='updatesNeeded' direction='out'/>"
    "<arg type='ai' name='idErrors' direction='out'/></method>"
    "<signal name='ItemsPropertiesUpdated'><arg type='a(ia{sv})'/><arg type='a(ia{sv})'/></signal>"
    "<signal name='LayoutUpdated'><arg type='u' name='revision'/><arg type='i' name='parent'/>"
    "</signal>"
    "<signal name='ItemActivationRequested'><arg type='i'/><arg type='u'/></signal>"
    "</interface></node>";

static GtkWidget *menu_child(struct ks_tray *t, int id)
{
    GList *kids = gtk_container_get_children(GTK_CONTAINER(t->menu));
    GtkWidget *w = g_list_nth_data(kids, (guint)(id - 1));
    g_list_free(kids);
    return w;
}

static GVariant *menu_props(GtkWidget *w)
{
    GVariantBuilder b;
    g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    if (GTK_IS_SEPARATOR_MENU_ITEM(w)) {
        g_variant_builder_add(&b, "{sv}", "type", g_variant_new_string("separator"));
        return g_variant_builder_end(&b);
    }
    const char *label = gtk_menu_item_get_label(GTK_MENU_ITEM(w));
    g_variant_builder_add(&b, "{sv}", "label", g_variant_new_string(label ? label : ""));
    g_variant_builder_add(&b, "{sv}", "enabled", g_variant_new_boolean(gtk_widget_get_sensitive(w)));
    if (GTK_IS_CHECK_MENU_ITEM(w)) {
        g_variant_builder_add(&b, "{sv}", "toggle-type", g_variant_new_string("checkmark"));
        g_variant_builder_add(
            &b, "{sv}", "toggle-state",
            g_variant_new_int32(gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(w)) ? 1 : 0));
    }
    return g_variant_builder_end(&b);
}

static GVariant *menu_layout(struct ks_tray *t)
{
    GVariantBuilder kids;
    g_variant_builder_init(&kids, G_VARIANT_TYPE("av"));
    GList *l = gtk_container_get_children(GTK_CONTAINER(t->menu));
    int id = 1;
    for (GList *i = l; i != NULL; i = i->next, id++) {
        GVariant *item = g_variant_new("(i@a{sv}@av)", id, menu_props(i->data),
                                       g_variant_new("av", NULL));
        g_variant_builder_add(&kids, "v", item);
    }
    g_list_free(l);
    GVariantBuilder rp;
    g_variant_builder_init(&rp, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&rp, "{sv}", "children-display", g_variant_new_string("submenu"));
    return g_variant_new("(i@a{sv}@av)", 0, g_variant_builder_end(&rp),
                         g_variant_builder_end(&kids));
}

static void menu_event(struct ks_tray *t, int id, const char *ev)
{
    if (strcmp(ev, "clicked") != 0)
        return;
    GtkWidget *w = menu_child(t, id);
    if (w != NULL && gtk_widget_get_sensitive(w))
        gtk_menu_item_activate(GTK_MENU_ITEM(w));
}

static GVariant *menu_get(GDBusConnection *c, const gchar *sender, const gchar *path,
                          const gchar *iface, const gchar *prop, GError **err, gpointer data)
{
    (void)c; (void)sender; (void)path; (void)iface; (void)err; (void)data;
    if (!strcmp(prop, "Version"))
        return g_variant_new_uint32(3);
    if (!strcmp(prop, "TextDirection"))
        return g_variant_new_string("ltr");
    if (!strcmp(prop, "Status"))
        return g_variant_new_string("normal");
    if (!strcmp(prop, "IconThemePath"))
        return g_variant_new_strv(NULL, 0);
    return NULL;
}

static void menu_call(GDBusConnection *c, const gchar *sender, const gchar *path,
                      const gchar *iface, const gchar *method, GVariant *params,
                      GDBusMethodInvocation *inv, gpointer data)
{
    (void)c; (void)sender; (void)path; (void)iface;
    struct ks_tray *t = data;
    if (!strcmp(method, "GetLayout")) {
        fill_menu(t);
        g_dbus_method_invocation_return_value(
            inv, g_variant_new("(u@(ia{sv}av))", t->menu_rev, menu_layout(t)));
    } else if (!strcmp(method, "GetGroupProperties")) {
        GVariant *ids = g_variant_get_child_value(params, 0);
        GVariantBuilder out;
        g_variant_builder_init(&out, G_VARIANT_TYPE("a(ia{sv})"));
        GVariantIter it;
        gint32 id;
        g_variant_iter_init(&it, ids);
        while (g_variant_iter_next(&it, "i", &id)) {
            GtkWidget *w = menu_child(t, id);
            if (w != NULL)
                g_variant_builder_add(&out, "(i@a{sv})", id, menu_props(w));
        }
        g_variant_unref(ids);
        g_dbus_method_invocation_return_value(inv,
                                              g_variant_new("(@a(ia{sv}))", g_variant_builder_end(&out)));
    } else if (!strcmp(method, "GetProperty")) {
        gint32 id;
        const gchar *name;
        g_variant_get(params, "(i&s)", &id, &name);
        GtkWidget *w = menu_child(t, id);
        GVariant *v = NULL;
        if (w != NULL) {
            GVariant *props = menu_props(w);
            v = g_variant_lookup_value(props, name, NULL);
            g_variant_unref(props);
        }
        if (v == NULL)
            g_dbus_method_invocation_return_dbus_error(inv, "org.freedesktop.DBus.Error.InvalidArgs",
                                                       "no such property");
        else
            g_dbus_method_invocation_return_value(inv, g_variant_new("(v)", v));
    } else if (!strcmp(method, "Event")) {
        gint32 id;
        const gchar *ev;
        g_variant_get(params, "(i&svu)", &id, &ev, NULL, NULL);
        menu_event(t, id, ev);
        g_dbus_method_invocation_return_value(inv, NULL);
    } else if (!strcmp(method, "EventGroup")) {
        GVariantIter it;
        gint32 id;
        const gchar *ev;
        GVariant *evs = g_variant_get_child_value(params, 0);
        g_variant_iter_init(&it, evs);
        while (g_variant_iter_next(&it, "(i&svu)", &id, &ev, NULL, NULL))
            menu_event(t, id, ev);
        g_variant_unref(evs);
        g_dbus_method_invocation_return_value(inv, g_variant_new("(ai)", NULL));
    } else if (!strcmp(method, "AboutToShow")) {
        fill_menu(t);
        g_dbus_method_invocation_return_value(inv, g_variant_new("(b)", TRUE));
    } else if (!strcmp(method, "AboutToShowGroup")) {
        fill_menu(t);
        g_dbus_method_invocation_return_value(inv, g_variant_new("(aiai)", NULL, NULL));
    } else {
        g_dbus_method_invocation_return_dbus_error(inv, "org.freedesktop.DBus.Error.UnknownMethod",
                                                   method);
    }
}

static void sni_changed(struct ks_tray *t)
{
    if (t->bus == NULL || t->sni_reg == 0)
        return;
    GError *err = NULL;
    if (t->menu_reg != 0) {
        g_dbus_connection_emit_signal(t->bus, NULL, MENU_PATH, "com.canonical.dbusmenu",
                                      "LayoutUpdated", g_variant_new("(ui)", ++t->menu_rev, 0),
                                      &err);
        g_clear_error(&err);
    }
    g_dbus_connection_emit_signal(t->bus, NULL, SNI_PATH, "org.kde.StatusNotifierItem", "NewIcon",
                                  NULL, &err);
    g_clear_error(&err);
    g_dbus_connection_emit_signal(t->bus, NULL, SNI_PATH, "org.kde.StatusNotifierItem",
                                  "NewToolTip", NULL, &err);
    g_clear_error(&err);
    g_dbus_connection_emit_signal(t->bus, NULL, SNI_PATH, "org.kde.StatusNotifierItem", "NewStatus",
                                  g_variant_new("(s)", t->alert ? "NeedsAttention" : "Active"),
                                  &err);
    g_clear_error(&err);
}

static void sni_registered(GObject *src, GAsyncResult *res, gpointer data)
{
    struct ks_tray *t = data;
    GError *err = NULL;
    GVariant *r = g_dbus_connection_call_finish(G_DBUS_CONNECTION(src), res, &err);
    if (r == NULL) {
        ks_warning("StatusNotifierWatcher: %s", err->message);
        g_clear_error(&err);
        return;
    }
    g_variant_unref(r);
    t->sni_ok = true;
    gtk_status_icon_set_visible(t->icon, FALSE);
    ks_info("tray: registered as a StatusNotifierItem (%s)", t->sni_service);
}

static void sni_watcher_appeared(GDBusConnection *c, const gchar *name, const gchar *owner,
                                 gpointer data)
{
    (void)name; (void)owner;
    struct ks_tray *t = data;
    g_dbus_connection_call(c, SNI_WATCHER, SNI_WATCHER_PATH, SNI_WATCHER,
                           "RegisterStatusNotifierItem", g_variant_new("(s)", t->sni_service),
                           NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, sni_registered, t);
}

static void sni_watcher_vanished(GDBusConnection *c, const gchar *name, gpointer data)
{
    (void)c; (void)name;
    struct ks_tray *t = data;
    t->sni_ok = false;
    gtk_status_icon_set_visible(t->icon, TRUE);
}

static void sni_setup(struct ks_tray *t)
{
    GError *err = NULL;
    t->bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
    if (t->bus == NULL) {
        ks_info("tray: no session bus, using the XEmbed icon only (%s)", err->message);
        g_clear_error(&err);
        return;
    }
    t->sni_info = g_dbus_node_info_new_for_xml(sni_xml, NULL);
    static const GDBusInterfaceVTable vt = {sni_call, sni_get, NULL, {0}};
    t->sni_reg = g_dbus_connection_register_object(t->bus, SNI_PATH, t->sni_info->interfaces[0],
                                                   &vt, t, NULL, &err);
    if (t->sni_reg == 0) {
        ks_warning("tray: can't export the StatusNotifierItem: %s", err->message);
        g_clear_error(&err);
        return;
    }
    t->menu_info = g_dbus_node_info_new_for_xml(menu_xml, NULL);
    static const GDBusInterfaceVTable mvt = {menu_call, menu_get, NULL, {0}};
    t->menu_reg = g_dbus_connection_register_object(t->bus, MENU_PATH,
                                                    t->menu_info->interfaces[0], &mvt, t, NULL,
                                                    &err);
    if (t->menu_reg == 0) {
        ks_warning("tray: can't export the dbusmenu: %s", err->message);
        g_clear_error(&err);
    }
    snprintf(t->sni_service, sizeof(t->sni_service), "org.kde.StatusNotifierItem-%d-1",
             (int)getpid());
    t->sni_name = g_bus_own_name_on_connection(t->bus, t->sni_service, G_BUS_NAME_OWNER_FLAGS_NONE,
                                               NULL, NULL, NULL, NULL);
    /* appears now or whenever the panel starts, and vanishes with it */
    t->sni_watch = g_bus_watch_name_on_connection(t->bus, SNI_WATCHER, G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                  sni_watcher_appeared, sni_watcher_vanished, t,
                                                  NULL);
}

static void sni_teardown(struct ks_tray *t)
{
    if (t->sni_watch)
        g_bus_unwatch_name(t->sni_watch);
    if (t->sni_reg)
        g_dbus_connection_unregister_object(t->bus, t->sni_reg);
    if (t->menu_reg)
        g_dbus_connection_unregister_object(t->bus, t->menu_reg);
    if (t->menu_info)
        g_dbus_node_info_unref(t->menu_info);
    if (t->sni_name)
        g_bus_unown_name(t->sni_name);
    if (t->sni_info)
        g_dbus_node_info_unref(t->sni_info);
    if (t->bus)
        g_object_unref(t->bus);
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

static void fill_menu(struct ks_tray *t)
{
    /* _on_show_menu() */
    t->filling = true;
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(t->autostart_item),
                                   ks_autostart_enabled(config_home()));
    t->filling = false;
}

static void on_popup(GtkStatusIcon *icon, guint button, guint time, gpointer data)
{
    struct ks_tray *t = data;
    fill_menu(t);
    gtk_menu_popup(GTK_MENU(t->menu), NULL, NULL, gtk_status_icon_position_menu, icon, button,
                   time);
}

/* from the StatusNotifierItem: no icon to anchor the menu, so the pointer */
static void show_menu(struct ks_tray *t, guint button, guint32 time)
{
    fill_menu(t);
    gtk_menu_popup(GTK_MENU(t->menu), NULL, NULL, NULL, NULL, button, time);
}

static void on_stats_item(GtkMenuItem *item, gpointer data)
{
    (void)item;
    struct ks_tray *t = data;
    if (t->on_open)
        t->on_open(t->ud);
}

static void do_activate(struct ks_tray *t)
{
    /* _on_tray_icon_activated(): the window; the click clears the alert */
    t->alert = false;
    ks_tray_update(t);
    if (t->on_open)
        t->on_open(t->ud);
}

static void on_activate(GtkStatusIcon *icon, gpointer data)
{
    (void)icon;
    do_activate(data);
}

struct ks_tray *ks_tray_new(struct ks_service *svc, void (*on_open)(void *),
                            void (*on_close)(void *), void *ud)
{
    struct ks_tray *t = calloc(1, sizeof(*t));
    if (t == NULL)
        return NULL;
    t->svc = svc;
    t->on_open = on_open;
    t->on_close = on_close;
    t->ud = ud;
    t->pix[ICON_OFF] = load_png(ks_res_tray_off_png, ks_res_tray_off_png_len);
    t->pix[ICON_WHITE] = load_png(ks_res_tray_enabled_png, ks_res_tray_enabled_png_len);
    t->pix[ICON_PAUSE] = load_png(ks_res_tray_pause_png, ks_res_tray_pause_png_len);
    t->pix[ICON_ALERT] = load_png(ks_res_tray_alert_png, ks_res_tray_alert_png_len);

    t->icon = gtk_status_icon_new_from_pixbuf(t->pix[ICON_OFF]);
    gtk_status_icon_set_title(t->icon, "Kisnitch");

    t->menu = gtk_menu_new();
    t->stats_item = gtk_menu_item_new_with_label(_("Open main window"));
    g_signal_connect(t->stats_item, "activate", G_CALLBACK(on_stats_item), t);
    t->fw_item = gtk_menu_item_new_with_label(_("Disable"));
    gtk_widget_set_sensitive(t->fw_item, FALSE);
    t->autostart_item = gtk_check_menu_item_new_with_label(_("Autostart"));
    GtkWidget *help = gtk_menu_item_new_with_label(_("Help"));
    GtkWidget *close = gtk_menu_item_new_with_label(_("Close"));
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
    sni_setup(t);
    ks_tray_update(t);
    return t;
}

void ks_tray_free(struct ks_tray *t)
{
    if (t == NULL)
        return;
    sni_teardown(t);
    gtk_widget_destroy(t->menu);
    g_object_unref(t->icon);
    for (int i = 0; i < NICONS; i++) {
        if (t->pix[i])
            g_object_unref(t->pix[i]);
    }
    free(t);
}
