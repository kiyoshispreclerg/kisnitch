/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/pidmonitor/main.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "daemon/procmon/cache.h"
#include "daemon/procmon/process.h"
#include "daemon/tasks/monitors.h"

struct pidmon {
    int pid;
    char *interval;
    struct ks_proc *p;
};

static int pidmon_start(struct ks_task *t, char *err, size_t errlen)
{
    struct pidmon *pm = t->priv;
    /* the cached process (a copy, so GetExtraInfo doesn't touch the cache),
     * with its tree; or NewProcess() */
    struct ks_proc *cached = ks_events_find(pm->pid);
    if (cached != NULL) {
        pm->p = ks_proc_clone(cached);
        if (pm->p != NULL && pm->p->ntree == 0) {
            ks_proc_get_parent(pm->p);
            ks_proc_build_tree(pm->p);
        }
    } else {
        pm->p = ks_proc_new_empty(pm->pid, "");
        if (pm->p != NULL && pm->pid > 0) {
            ks_proc_get_details(pm->p);
            ks_proc_get_parent(pm->p);
            ks_proc_build_tree(pm->p);
        }
    }
    if (pm->p == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    return ks_task_parse_interval(pm->interval, &t->interval_ns, err, errlen);
}

static enum ks_task_status pidmon_run(struct ks_task *t, char **data, char *err,
                                      size_t errlen)
{
    struct pidmon *pm = t->priv;
    /* GetExtraInfo never fails upstream: once the process exits, its last
     * values keep being sent */
    ks_proc_get_extra_info(pm->p);
    *data = ks_proc_json(pm->p);
    if (*data == NULL) {
        snprintf(err, errlen, "out of memory");
        return KS_TASK_ERROR;
    }
    return KS_TASK_RESULT;
}

static void pidmon_free(void *priv)
{
    struct pidmon *pm = priv;
    if (pm == NULL)
        return;
    ks_debug("[tasks.PIDMonitor] stopped (%d)", pm->pid);
    ks_proc_unref(pm->p);
    free(pm->interval);
    free(pm);
}

static const struct ks_task_ops pidmon_ops = {pidmon_start, pidmon_run, pidmon_free};

struct ks_task *ks_pidmon_new(int pid, const char *interval, bool temporary)
{
    struct pidmon *pm = calloc(1, sizeof(*pm));
    if (pm == NULL)
        return NULL;
    pm->pid = pid;
    if ((pm->interval = strdup(interval != NULL ? interval : "")) == NULL) {
        free(pm);
        return NULL;
    }
    char name[64];
    snprintf(name, sizeof(name), "%s-%d", KS_TASK_PID_MONITOR, pid);
    struct ks_task *t = ks_task_new(name, &pidmon_ops, pm);
    if (t != NULL)
        t->temporary = temporary;
    return t;
}
