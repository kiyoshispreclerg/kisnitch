/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The system firewall configuration file of the daemon: port of upstream
 * daemon/firewall/config/config.go (loading, watching and saving
 * system-fw.json) and the error channel of
 * daemon/firewall/common/common.go. The configuration itself is in
 * common/sysfw.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_sysfw_conf owns its configuration, its path and its inotify fd
 * (watched on the event loop, which must outlive it). struct ks_fw_errors
 * owns its queued strings.
 */
#ifndef KS_DAEMON_FW_SYSFW_H
#define KS_DAEMON_FW_SYSFW_H

#include <stdbool.h>
#include <stddef.h>

#include "common/sysfw.h"

/* ---- the configuration file (config.Config) ------------------------ */

struct ks_evloop;
typedef void (*ks_sysfw_cb)(void *data);

struct ks_sysfw_conf {
    struct ks_sysfw cfg; /* SysConfig */
    char *file;
    int inotify_fd;
    bool watching;
    struct ks_evloop *loop;
    ks_sysfw_cb preload; /* before (re)loading: delete the old rules */
    ks_sysfw_cb reload;  /* after a change on disk: add the new rules */
    void *data;
};

/* NewSystemFwConfig. The inotify fd is watched on `loop` (may be NULL in
 * tests: no monitoring). Returns -1 on OOM. */
int ks_sysfw_conf_init(struct ks_sysfw_conf *c, struct ks_evloop *loop,
                       const char *path, ks_sysfw_cb preload, ks_sysfw_cb reload,
                       void *data);
/* StopConfigWatcher, and frees everything (the configuration included). */
void ks_sysfw_conf_destroy(struct ks_sysfw_conf *c);
/* SetConfigFile: ignored if empty. */
void ks_sysfw_conf_set_file(struct ks_sysfw_conf *c, const char *file);
/* LoadDiskConfiguration: preload, parse, watch the file, and with `reload`
 * call the reload callback. 0 or -1 (logged). */
int ks_sysfw_conf_load(struct ks_sysfw_conf *c, bool reload);
/* SaveConfiguration: writes `raw` with mode 0600. The watcher reloads it. */
int ks_sysfw_conf_save(struct ks_sysfw_conf *c, const char *raw, size_t len);

/* ---- common.Common.ErrChan ----------------------------------------- */

#define KS_FW_ERRORS_CAP 100

struct ks_fw_errors {
    char *items[KS_FW_ERRORS_CAP];
    size_t head, n;
};

/* SendError: logs a warning and queues it (dropping the oldest when full). */
void ks_fw_errors_send(struct ks_fw_errors *q, const char *err);
bool ks_fw_errors_empty(const struct ks_fw_errors *q);
/* Takes the oldest error (caller frees), or NULL. */
char *ks_fw_errors_pop(struct ks_fw_errors *q);
void ks_fw_errors_clear(struct ks_fw_errors *q);

#endif
