/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/firewall/config/config.go, the Serialize() and
 * Deserialize() of the firewalls, and common.Common's error channel.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/fw/sysfw.h"

#include <errno.h>
#include <fcntl.h>
#include <stdalign.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "daemon/evloop.h"

/* ---- config.Config ----------------------------------------------------- */

static void on_conf_event(int fd, uint32_t events, void *data);

int ks_sysfw_conf_init(struct ks_sysfw_conf *c, struct ks_evloop *loop,
                       const char *path, ks_sysfw_cb preload, ks_sysfw_cb reload,
                       void *data)
{
    memset(c, 0, sizeof(*c));
    c->inotify_fd = -1;
    c->file = strdup(path != NULL ? path : "");
    if (c->file == NULL)
        return -1;
    c->loop = loop;
    c->preload = preload;
    c->reload = reload;
    c->data = data;
    if (loop != NULL) {
        c->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (c->inotify_fd < 0) {
            ks_warning("Error creating firewall config watcher: %s", strerror(errno));
        } else if (ks_evloop_add_fd(loop, c->inotify_fd, EPOLLIN, on_conf_event, c) < 0) {
            close(c->inotify_fd);
            c->inotify_fd = -1;
        }
    }
    return 0;
}

void ks_sysfw_conf_destroy(struct ks_sysfw_conf *c)
{
    if (c->inotify_fd >= 0) {
        if (c->loop != NULL)
            ks_evloop_del_fd(c->loop, c->inotify_fd);
        close(c->inotify_fd);
    }
    ks_debug("stop monitoring firewall config file");
    ks_sysfw_free(&c->cfg);
    free(c->file);
    memset(c, 0, sizeof(*c));
    c->inotify_fd = -1;
}

void ks_sysfw_conf_set_file(struct ks_sysfw_conf *c, const char *file)
{
    if (file == NULL || file[0] == '\0') {
        ks_debug("Firewall configuration file not provided, ignoring");
        return;
    }
    char *f = strdup(file);
    if (f == NULL)
        return;
    free(c->file);
    c->file = f;
}

/* watcher.Remove(file) + watcher.Add(file). A single watch per fd: the
 * inotify descriptor only ever watches this file, so re-adding the path
 * moves the watch to the current inode. */
static int watch_file(struct ks_sysfw_conf *c)
{
    if (c->inotify_fd < 0)
        return 0;
    if (inotify_add_watch(c->inotify_fd, c->file, IN_MODIFY | IN_DELETE_SELF) < 0) {
        ks_error("Could not watch firewall configuration: %s", strerror(errno));
        return -1;
    }
    c->watching = true;
    return 0;
}

/* loadConfiguration */
static int load_configuration(struct ks_sysfw_conf *c, const char *raw, size_t len)
{
    /* delete old system rules, that may be different from the new ones */
    if (c->preload != NULL)
        c->preload(c->data);

    struct ks_sysfw n;
    char err[512];
    if (ks_sysfw_parse(raw, len, &n, err, sizeof(err)) < 0) {
        /* only logged, giving the user a chance to write a valid config */
        ks_error("Error parsing firewall configuration %s: %s", c->file, err);
        return -1;
    }
    ks_sysfw_free(&c->cfg);
    c->cfg = n;
    ks_info("fw configuration loaded");
    return 0;
}

int ks_sysfw_conf_load(struct ks_sysfw_conf *c, bool reload)
{
    char err[512];
    size_t len = 0;
    char *raw = ks_read_file(c->file, KS_SYSFW_MAX_SIZE, &len, err, sizeof(err));
    if (raw == NULL) {
        ks_error("Error reading firewall configuration from disk %s: %s", c->file, err);
        return -1;
    }
    int ret = load_configuration(c, raw, len);
    free(raw);
    /* Watch the file even when it's malformed, so fixing it is noticed
     * (upstream's intent; it returns before adding the watch). */
    if (watch_file(c) < 0 || ret < 0)
        return -1;
    if (reload && c->reload != NULL)
        c->reload(c->data);
    return 0;
}

int ks_sysfw_conf_save(struct ks_sysfw_conf *c, const char *raw, size_t len)
{
    char err[512];
    if (chmod(c->file, 0600) < 0)
        ks_warning("unable to set system-fw.json permissions: %s", strerror(errno));
    if (ks_write_file_safe(c->file, raw, len, 0600, ks_check_json_object, err,
                           sizeof(err)) < 0) {
        ks_error("writing firewall configuration to disk: %s", err);
        return -1;
    }
    /* a new file is created 0600, an existing one keeps its mode */
    chmod(c->file, 0600);
    return 0;
}

/* monitorConfigWorker: writes and removals reload the configuration. */
static void on_conf_event(int fd, uint32_t events, void *data)
{
    (void)events;
    struct ks_sysfw_conf *c = data;
    alignas(struct inotify_event) char buf[4096];
    bool reload = false;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        for (ssize_t off = 0; off < n;) {
            const struct inotify_event *ev = (const struct inotify_event *)(buf + off);
            if (ev->mask & (IN_MODIFY | IN_DELETE_SELF))
                reload = true;
            off += (ssize_t)(sizeof(*ev) + ev->len);
        }
    }
    if (reload && c->watching)
        ks_sysfw_conf_load(c, true);
}

/* ---- ErrChan ------------------------------------------------------------ */

void ks_fw_errors_send(struct ks_fw_errors *q, const char *err)
{
    ks_warning("%s", err);
    char *s = strdup(err);
    if (s == NULL)
        return;
    if (q->n == KS_FW_ERRORS_CAP) {
        ks_debug("fw errors channel full, emptying errChan");
        free(ks_fw_errors_pop(q));
    }
    q->items[(q->head + q->n) % KS_FW_ERRORS_CAP] = s;
    q->n++;
}

bool ks_fw_errors_empty(const struct ks_fw_errors *q)
{
    return q->n == 0;
}

char *ks_fw_errors_pop(struct ks_fw_errors *q)
{
    if (q->n == 0)
        return NULL;
    char *s = q->items[q->head];
    q->items[q->head] = NULL;
    q->head = (q->head + 1) % KS_FW_ERRORS_CAP;
    q->n--;
    return s;
}

void ks_fw_errors_clear(struct ks_fw_errors *q)
{
    char *s;
    while ((s = ks_fw_errors_pop(q)) != NULL)
        free(s);
    q->head = 0;
}
