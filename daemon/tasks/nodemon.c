/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/nodemonitor/main.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>

#include "cJSON.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/tasks/monitors.h"

struct nodemon {
    char *node;
    char *interval;
};

static cJSON *zeros(int n)
{
    cJSON *a = cJSON_CreateArray();
    for (int i = 0; a != NULL && i < n; i++) {
        cJSON *z = cJSON_CreateRaw("0");
        if (z == NULL || !cJSON_AddItemToArray(a, z)) {
            cJSON_Delete(z);
            cJSON_Delete(a);
            return NULL;
        }
    }
    return a;
}

char *ks_nodemon_sysinfo_json(void)
{
    struct sysinfo si;
    memset(&si, 0, sizeof(si));
    if (sysinfo(&si) < 0)
        return NULL;
    /* syscall.Sysinfo_t: on 64-bit Linux the C padding shows up as
     * Pad_cgo_0 and Pad_cgo_1, and X_f is empty; on 32-bit, X_f has 8
     * bytes and there's no padding. Go zeroes the struct, as here. */
    bool lp64 = sizeof(long) == 8;
    cJSON *o = cJSON_CreateObject();
    cJSON *loads = cJSON_CreateArray();
    bool ok = o != NULL && loads != NULL && ks_json_add_int(o, "Uptime", si.uptime) &&
              cJSON_AddItemToObject(o, "Loads", loads);
    if (!ok)
        cJSON_Delete(loads);
    for (int i = 0; ok && i < 3; i++) {
        char b[24];
        snprintf(b, sizeof(b), "%lu", si.loads[i]);
        cJSON *l = cJSON_CreateRaw(b);
        ok = l != NULL && cJSON_AddItemToArray(loads, l);
        if (!ok)
            cJSON_Delete(l);
    }
    ok = ok && ks_json_add_uint(o, "Totalram", si.totalram) &&
         ks_json_add_uint(o, "Freeram", si.freeram) &&
         ks_json_add_uint(o, "Sharedram", si.sharedram) &&
         ks_json_add_uint(o, "Bufferram", si.bufferram) &&
         ks_json_add_uint(o, "Totalswap", si.totalswap) &&
         ks_json_add_uint(o, "Freeswap", si.freeswap) &&
         ks_json_add_uint(o, "Procs", si.procs) && ks_json_add_uint(o, "Pad", si.pad);
    if (ok && lp64)
        ok = cJSON_AddItemToObject(o, "Pad_cgo_0", zeros(4));
    ok = ok && ks_json_add_uint(o, "Totalhigh", si.totalhigh) &&
         ks_json_add_uint(o, "Freehigh", si.freehigh) &&
         ks_json_add_uint(o, "Unit", si.mem_unit) &&
         cJSON_AddItemToObject(o, "X_f", zeros(lp64 ? 0 : 8));
    if (ok && lp64)
        ok = cJSON_AddItemToObject(o, "Pad_cgo_1", zeros(4));
    char *s = ok ? ks_json_print_go(o, false) : NULL;
    cJSON_Delete(o);
    if (s == NULL)
        errno = ENOMEM;
    return s;
}

static int nodemon_start(struct ks_task *t, char *err, size_t errlen)
{
    struct nodemon *nm = t->priv;
    return ks_task_parse_interval(nm->interval, &t->interval_ns, err, errlen);
}

static enum ks_task_status nodemon_run(struct ks_task *t, char **data, char *err,
                                       size_t errlen)
{
    (void)t;
    *data = ks_nodemon_sysinfo_json();
    if (*data == NULL) {
        snprintf(err, errlen, "%s", strerror(errno));
        return KS_TASK_ERROR;
    }
    return KS_TASK_RESULT;
}

static void nodemon_free(void *priv)
{
    struct nodemon *nm = priv;
    if (nm == NULL)
        return;
    ks_debug("[tasks.NodeMonitor] stopped (%s)", nm->node);
    free(nm->node);
    free(nm->interval);
    free(nm);
}

static const struct ks_task_ops nodemon_ops = {nodemon_start, nodemon_run, nodemon_free};

struct ks_task *ks_nodemon_new(const char *node, const char *interval, bool temporary)
{
    struct nodemon *nm = calloc(1, sizeof(*nm));
    if (nm == NULL)
        return NULL;
    nm->node = strdup(node != NULL ? node : "");
    nm->interval = strdup(interval != NULL ? interval : "");
    if (nm->node == NULL || nm->interval == NULL) {
        nodemon_free(nm);
        return NULL;
    }
    size_t len = strlen(KS_TASK_NODE_MONITOR) + strlen(nm->node) + 2;
    char *name = malloc(len);
    if (name == NULL) {
        nodemon_free(nm);
        return NULL;
    }
    snprintf(name, len, "%s-%s", KS_TASK_NODE_MONITOR, nm->node);
    struct ks_task *t = ks_task_new(name, &nodemon_ops, nm);
    free(name);
    if (t != NULL)
        t->temporary = temporary;
    return t;
}
