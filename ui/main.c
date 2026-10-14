/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * kisnitch-gtk: the UI. Port of upstream ui/bin/opensnitch-ui: arguments,
 * single instance, the gRPC server address and options, and the wiring of
 * the service, the tray and the pop-up.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <errno.h>
#include <fcntl.h>
#include <glib-unix.h>
#include <gtk/gtk.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/log.h"
#include "ui/desktop.h"
#include "ui/prompt.h"
#include "ui/server.h"
#include "ui/service.h"
#include "ui/settings.h"
#include "ui/tray.h"

#define APP_ID "io.github.evilsocket.opensnitch"
#define DEFAULT_SOCKET "unix:///tmp/osui.sock"

struct app {
    struct ks_settings settings;
    struct ks_service *svc;
    struct ks_ui_server *server;
    struct ks_tray *tray;
    struct ks_prompt *prompt;
    struct ks_desktop desktop;
    int instance_fd;
    char instance_path[PATH_MAX];
    GtkWidget *version_dialog;
};

static struct app app = {.instance_fd = -1};

/* ---- service callbacks ------------------------------------------------- */

static void on_prompt(void *ud, struct ks_ask *ask)
{
    struct app *a = ud;
    ks_prompt_ask(a->prompt, ask);
}

static void on_status(void *ud)
{
    struct app *a = ud;
    if (a->tray)
        ks_tray_status_changed(a->tray);
}

static void on_message(void *ud, const char *title, const char *body)
{
    (void)title;
    (void)body;
    struct app *a = ud;
    /* desktop notifications come with phase 10 (NOTIFY=1); the message
     * went to the log, and the tray shows the alert icon */
    if (a->tray)
        ks_tray_alert(a->tray);
}

static void on_version_warning(void *ud, const char *daemon, const char *ui)
{
    struct app *a = ud;
    if (a->version_dialog != NULL)
        return;
    a->version_dialog = gtk_message_dialog_new_with_markup(
        NULL, 0, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
        "You are running version <b>%s</b> of the daemon, while the UI is at version "
        "<b>%s</b>, they might not be fully compatible.",
        daemon, ui);
    gtk_window_set_title(GTK_WINDOW(a->version_dialog), "OpenSnitch version mismatch!");
    g_signal_connect_swapped(a->version_dialog, "response", G_CALLBACK(gtk_widget_hide),
                             a->version_dialog);
    gtk_widget_show(a->version_dialog);
}

/* ---- single instance (QLocalServer at $XDG_RUNTIME_DIR/opensnitch) ----- */

/* get_run_opensnitch_dir() */
static void run_dir(char *buf, size_t len)
{
    const char *rt = getenv("XDG_RUNTIME_DIR");
    char fallback[PATH_MAX];
    if (rt == NULL || rt[0] == '\0') {
        snprintf(fallback, sizeof(fallback), "/tmp/opensnitch-%s", g_get_user_name());
        mkdir(fallback, 0700);
        rt = fallback;
    }
    if (strstr(rt, "opensnitch") != NULL) {
        snprintf(buf, len, "%s", rt);
    } else {
        int n = snprintf(buf, len, "%s/%s", rt, "opensnitch");
        if (n > 0 && (size_t)n < len)
            mkdir(buf, 0700);
    }
}

static gboolean on_instance(gint fd, GIOCondition cond, gpointer data)
{
    (void)cond;
    (void)data;
    int c = accept(fd, NULL, NULL);
    if (c >= 0) {
        /* OpenWindow(): the main window comes with phase 7 */
        ks_info("another instance asked to open the main window");
        close(c);
    }
    return G_SOURCE_CONTINUE;
}

/* -1: another instance is running */
static int single_instance(struct app *a)
{
    char dir[PATH_MAX];
    run_dir(dir, sizeof(dir));
    struct sockaddr_un un = {.sun_family = AF_UNIX};
    int n = snprintf(a->instance_path, sizeof(a->instance_path), "%s/%s", dir, APP_ID);
    if (n < 0 || (size_t)n >= sizeof(un.sun_path))
        return 0; /* can't have it: just run */
    memcpy(un.sun_path, a->instance_path, (size_t)n + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == 0) {
        close(fd);
        return -1;
    }
    /* removeServer() + listen(), UserAccessOption */
    unlink(a->instance_path);
    mode_t um = umask(077);
    if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0 || listen(fd, 4) < 0) {
        umask(um);
        close(fd);
        a->instance_path[0] = '\0';
        return 0;
    }
    umask(um);
    a->instance_fd = fd;
    g_unix_fd_add(fd, G_IO_IN, on_instance, a);
    return 0;
}

/* Utils.create_socket_dirs() */
static void create_socket_dirs(void)
{
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "/run/user/%u", (unsigned)getuid());
    if (access(p, F_OK) == 0) {
        snprintf(p, sizeof(p), "/run/user/%u/opensnitch", (unsigned)getuid());
        mkdir(p, 0700);
    }
    snprintf(p, sizeof(p), "/var/run/user/%u", (unsigned)getuid());
    if (access(p, F_OK) == 0) {
        snprintf(p, sizeof(p), "/var/run/user/%u/opensnitch", (unsigned)getuid());
        mkdir(p, 0700);
    }
}

/* ---- exit -------------------------------------------------------------- */

static void on_close(void *ud)
{
    /* _on_close() */
    struct app *a = ud;
    ks_service_closing(a->svc);
    ks_prompt_close(a->prompt);
    gtk_main_quit();
}

static gboolean on_signal(gpointer data)
{
    on_close(data);
    return G_SOURCE_REMOVE;
}

static gboolean on_desktop_inotify(gint fd, GIOCondition cond, gpointer data)
{
    (void)fd;
    (void)cond;
    ks_desktop_on_inotify(data);
    return G_SOURCE_CONTINUE;
}

/* ---- main -------------------------------------------------------------- */

static void usage(FILE *out)
{
    fprintf(out,
            "usage: kisnitch-gtk [options]\n"
            "  --socket ADDR      gRPC address to listen on (default " DEFAULT_SOCKET ",\n"
            "                     or global/server_address in settings.conf).\n"
            "                     unix:///path, unix-abstract:name, unix:@name, [::]:50051\n"
            "  --socket-auth T    simple (TLS: not yet supported)\n"
            "  --max-clients N    max number of connected nodes\n"
            "  --max-workers N    accepted for compatibility (no worker threads here)\n"
            "  --background       start without showing anything\n"
            "  --debug            debug logs\n"
            "  --version          print the version and exit\n");
}

int main(int argc, char **argv)
{
    const char *socket_arg = NULL, *auth = NULL;
    int max_clients = 0;
    bool debug = false;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "--socket") == 0 && v) {
            socket_arg = v;
            i++;
        } else if (strcmp(a, "--socket-auth") == 0 && v) {
            auth = v;
            i++;
        } else if (strcmp(a, "--max-clients") == 0 && v) {
            max_clients = atoi(v);
            i++;
        } else if ((strcmp(a, "--max-workers") == 0 || strcmp(a, "--tls-ca-cert") == 0 ||
                    strcmp(a, "--tls-cert") == 0 || strcmp(a, "--tls-key") == 0) && v) {
            i++;
        } else if (strcmp(a, "--debug") == 0) {
            debug = true;
        } else if (strcmp(a, "--debug-grpc") == 0 || strcmp(a, "--background") == 0) {
            /* nothing to show at start anyway (the main window: phase 7) */
        } else if (strcmp(a, "--version") == 0) {
            printf("kisnitch-gtk %s\n", KS_VERSION);
            return 0;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            usage(stderr);
            return 2;
        }
    }

    ks_log_set_level(debug ? KS_LOG_DEBUG : KS_LOG_INFO);
    printf("\t ~ Kisnitch GUI - %s ~\n", KS_VERSION);
    printf("%s\n\n", "--------------------------------------------------");

    gtk_init(&argc, &argv);

    char path[PATH_MAX];
    if (ks_settings_default_path(path, sizeof(path)) < 0 ||
        ks_settings_open(&app.settings, path) < 0) {
        fprintf(stderr, "can't read the settings\n");
        return 1;
    }
    ks_settings_init_defaults(&app.settings);

    if (auth == NULL)
        auth = ks_settings_raw(&app.settings, KS_CFG_AUTH_TYPE);
    if (auth != NULL && auth[0] != '\0' && strcmp(auth, "simple") != 0) {
        fprintf(stderr, "auth type %s: TLS is not supported yet\n", auth);
        return 1;
    }

    create_socket_dirs();
    if (single_instance(&app) < 0) {
        printf("GUI already running, opening its window and exiting.\n");
        return 0;
    }

    /* the address: --socket, or the setting if usable */
    char addr[PATH_MAX];
    snprintf(addr, sizeof(addr), "%s", DEFAULT_SOCKET);
    if (socket_arg != NULL) {
        snprintf(addr, sizeof(addr), "%s", socket_arg);
    } else {
        char *cfg = ks_settings_get_string(&app.settings, KS_CFG_DEFAULT_SERVER_ADDR);
        if (cfg != NULL && cfg[0] != '\0') {
            if (strncmp(cfg, "unix://", 7) == 0) {
                char *dir = g_path_get_dirname(cfg + 7);
                if (access(dir, F_OK) != 0)
                    printf("WARNING: unix socket path does not exist, using %s, %s\n",
                           DEFAULT_SOCKET, cfg);
                else
                    snprintf(addr, sizeof(addr), "%s", cfg);
                g_free(dir);
            } else {
                snprintf(addr, sizeof(addr), "%s", cfg);
            }
        }
        free(cfg);
    }
    char *maxlen = ks_settings_get_string(&app.settings, "global/server_max_message_length");
    struct ks_ui_server_opts opts = {
        .address = addr,
        .max_msg = ks_ui_max_msg_length(maxlen),
        .max_clients = max_clients,
    };
    free(maxlen);

    static const struct ks_service_ops ops = {
        .prompt = on_prompt,
        .status_changed = on_status,
        .message = on_message,
        .version_warning = on_version_warning,
    };
    app.svc = ks_service_new(&app.settings, &ops, &app);
    ks_desktop_init(&app.desktop, NULL, NULL);
    int dfd = ks_desktop_watch(&app.desktop);
    if (dfd >= 0)
        g_unix_fd_add(dfd, G_IO_IN, on_desktop_inotify, &app.desktop);
    app.prompt = ks_prompt_new(app.svc, &app.desktop);
    app.tray = ks_tray_new(app.svc, on_close, &app);

    printf("[server] addr: %s\n", addr);
    char err[512];
    app.server = ks_ui_server_new(&opts, app.svc, err, sizeof(err));
    if (app.server == NULL) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }

    g_unix_signal_add(SIGINT, on_signal, &app);
    g_unix_signal_add(SIGTERM, on_signal, &app);
    gtk_main();

    ks_ui_server_free(app.server);
    ks_prompt_free(app.prompt);
    ks_tray_free(app.tray);
    ks_service_free(app.svc);
    ks_desktop_free(&app.desktop);
    if (app.version_dialog)
        gtk_widget_destroy(app.version_dialog);
    ks_settings_close(&app.settings);
    if (app.instance_fd >= 0) {
        close(app.instance_fd);
        unlink(app.instance_path);
    }
    return 0;
}
