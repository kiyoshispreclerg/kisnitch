/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/load.go and daemon/tasks/config (main.go,
 * monitor.go, utils.go).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "cJSON.h"
#include "common/duration.h"
#include "common/json_schema.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/evloop.h"
#include "daemon/tasks/disk.h"

#define TASKS_FILE_MAX (4u * 1024 * 1024)
/* liveReloadWorker: "the events may occur too rapidly, and sometimes the
 * file does not exist yet" */
#define CHANGE_DELAY_NS KS_SECOND

/* config.TaskConfig and TasksList */
struct task_config {
    char *name;
    char *config_file;
    bool enabled;
};
struct tasks_list {
    struct ks_array tasks;
};

static const struct ks_schema_field task_config_fields[] = {
    KS_FIELD(struct task_config, "Name", KS_T_STRING, name),
    KS_FIELD(struct task_config, "ConfigFile", KS_T_STRING, config_file),
    KS_FIELD(struct task_config, "Enabled", KS_T_BOOL, enabled),
};
static const struct ks_schema task_config_schema =
    KS_SCHEMA("config.TaskConfig", struct task_config, task_config_fields);
static const struct ks_schema_field tasks_list_fields[] = {
    KS_FIELD_SUB(struct tasks_list, "Tasks", KS_T_ARRAY, tasks, task_config_schema),
};
static const struct ks_schema tasks_list_schema =
    KS_SCHEMA("config.TasksList", struct tasks_list, tasks_list_fields);

struct watch {
    int wd;
    char *path;
};

struct pending {
    struct ks_taskloader *l;
    struct ks_timer *timer;
    char *file;
    struct pending *next;
};

struct ks_taskloader {
    struct ks_taskmgr *mgr;
    struct ks_evloop *loop;
    char *cfg_file;       /* Loader.CfgFile */
    char *reload_arg;     /* the argument of the last LoadTaskFile */
    struct tasks_list list; /* Loader.Tasks */
    int ifd;              /* the fsnotify watcher */
    bool live;            /* liveReloadRunning */
    struct watch *watches;
    size_t nwatches;
    struct pending *pending;
};

static char *xstrdup(const char *s)
{
    return strdup(s != NULL ? s : "");
}

/* ---- the watcher ------------------------------------------------------ */

static void add_watch(struct ks_taskloader *l, const char *path, bool list)
{
    int wd = inotify_add_watch(l->ifd, path, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF | IN_ATTRIB);
    if (wd < 0) {
        if (list)
            ks_error("[tasks] Could not watch path %s: %s", path, strerror(errno));
        else
            ks_error("[tasks] Loader, could not watch path %s: %s", path, strerror(errno));
        return;
    }
    for (size_t i = 0; i < l->nwatches; i++)
        if (l->watches[i].wd == wd)
            return;
    struct watch *w = realloc(l->watches, (l->nwatches + 1) * sizeof(*w));
    if (w == NULL)
        return;
    l->watches = w;
    if ((w[l->nwatches].path = strdup(path)) == NULL)
        return;
    w[l->nwatches].wd = wd;
    l->nwatches++;
}

static void drop_watch(struct ks_taskloader *l, size_t i)
{
    free(l->watches[i].path);
    l->watches[i] = l->watches[--l->nwatches];
}

/* RemoveWatch */
static void remove_watch(struct ks_taskloader *l, const char *path)
{
    for (size_t i = 0; i < l->nwatches; i++) {
        if (strcmp(l->watches[i].path, path) == 0) {
            inotify_rm_watch(l->ifd, l->watches[i].wd);
            drop_watch(l, i);
            return;
        }
    }
}

/* AddWatches: run before waiting for each event, so watches lost to a
 * removal or a rename come back. */
static void add_watches(struct ks_taskloader *l)
{
    if (l->ifd < 0 || !l->live)
        return;
    add_watch(l, l->cfg_file, true);
    for (size_t i = 0; i < l->list.tasks.len; i++) {
        const struct task_config *t = KS_ARRAY_ITEM(l->list.tasks, struct task_config, i);
        if (t->config_file[0] == '\0') {
            ks_warning("[tasks] Loader watch, \"configfile\" field missing, skipping task "
                       "%s: enabled: %s, %s",
                       t->name, t->enabled ? "true" : "false", t->config_file);
            continue;
        }
        if (!t->enabled)
            continue;
        ks_debug("[tasks] Loader watching %s: %s, %s", t->name, t->enabled ? "true" : "false",
                 t->config_file);
        add_watch(l, t->config_file, false);
    }
}

static void pending_free(struct ks_taskloader *l, struct pending *p)
{
    for (struct pending **pp = &l->pending; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == p) {
            *pp = p->next;
            break;
        }
    }
    if (p->timer != NULL)
        ks_evloop_cancel_timer(l->loop, p->timer);
    free(p->file);
    free(p);
}

static void on_change_timer(void *data)
{
    struct pending *p = data;
    struct ks_taskloader *l = p->l;
    p->timer = NULL; /* one-shot: the loop frees it */
    char *file = p->file;
    p->file = NULL;
    pending_free(l, p);
    ks_taskloader_file_changed(l, file);
    free(file);
}

static void on_inotify(int fd, uint32_t events, void *data)
{
    (void)events;
    struct ks_taskloader *l = data;
    union {
        struct inotify_event ev;
        char buf[4096];
    } u;
    ssize_t n;
    while ((n = read(fd, u.buf, sizeof(u.buf))) > 0) {
        for (char *p = u.buf; p < u.buf + n;) {
            const struct inotify_event *ev = (const struct inotify_event *)(void *)p;
            p += sizeof(*ev) + ev->len;
            const char *path = NULL;
            size_t wi = 0;
            for (; wi < l->nwatches; wi++) {
                if (l->watches[wi].wd == ev->wd) {
                    path = l->watches[wi].path;
                    break;
                }
            }
            if (path == NULL)
                continue;
            size_t pl = strlen(path);
            bool json = pl >= 5 && strcmp(path + pl - 5, ".json") == 0;
            if (json && (ev->mask & (IN_MODIFY | IN_MOVE_SELF))) {
                ks_important("Tasks file changed %s, reloading ...", path);
                /* one reload per file and wait (upstream queues one per event) */
                bool queued = false;
                for (struct pending *q = l->pending; q != NULL; q = q->next)
                    queued = queued || strcmp(q->file, path) == 0;
                struct pending *q = queued ? NULL : calloc(1, sizeof(*q));
                if (q != NULL) {
                    q->l = l;
                    q->file = strdup(path);
                    q->timer = ks_evloop_add_timer(l->loop, CHANGE_DELAY_NS, 0, on_change_timer, q);
                    q->next = l->pending;
                    l->pending = q;
                    if (q->file == NULL || q->timer == NULL)
                        pending_free(l, q);
                }
            }
            if (ev->mask & IN_IGNORED)
                drop_watch(l, wi);
        }
    }
    add_watches(l);
}

/* ---- loading ---------------------------------------------------------- */

/* config.LoadTaskData: TaskData{Parent, Name, Data map[string]interface{}} */
struct task_data {
    char *parent, *name;
    cJSON *data; /* NULL: a nil map */
};

static void task_data_free(struct task_data *d)
{
    free(d->parent);
    free(d->name);
    cJSON_Delete(d->data);
    memset(d, 0, sizeof(*d));
}

static int load_task_data(const char *path, struct task_data *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    char e[512];
    size_t len;
    char *raw = ks_read_file(path, TASKS_FILE_MAX, &len, e, sizeof(e));
    if (raw == NULL) {
        snprintf(err, errlen, "error opening task file %s: %s", path, e);
        return -1;
    }
    cJSON *j = ks_json_parse(raw, len, e, sizeof(e));
    free(raw);
    const cJSON *parent = NULL, *name = NULL, *data = NULL;
    if (j != NULL && !cJSON_IsObject(j) && !cJSON_IsNull(j)) {
        snprintf(e, sizeof(e), "(root): expected config.TaskData, got %s",
                 cJSON_IsArray(j) ? "array" : "value");
    } else if (j != NULL) {
        /* the last of duplicate keys wins, case-insensitively */
        const cJSON *c;
        cJSON_ArrayForEach(c, j)
        {
            if (strcasecmp(c->string, "parent") == 0)
                parent = c;
            else if (strcasecmp(c->string, "name") == 0)
                name = c;
            else if (strcasecmp(c->string, "data") == 0)
                data = c;
        }
        if (parent && !cJSON_IsString(parent) && !cJSON_IsNull(parent))
            snprintf(e, sizeof(e), "Parent: expected string");
        else if (name && !cJSON_IsString(name) && !cJSON_IsNull(name))
            snprintf(e, sizeof(e), "Name: expected string");
        else if (data && !cJSON_IsObject(data) && !cJSON_IsNull(data))
            snprintf(e, sizeof(e), "Data: expected map[string]interface {}");
        else
            e[0] = '\0';
    }
    if (j == NULL || e[0] != '\0') {
        snprintf(err, errlen, "error unmarshalling task file %s: %s", path, e);
        cJSON_Delete(j);
        return -1;
    }
    out->parent = xstrdup(cJSON_IsString(parent) ? parent->valuestring : "");
    out->name = xstrdup(cJSON_IsString(name) ? name->valuestring : "");
    if (cJSON_IsObject(data))
        out->data = cJSON_Duplicate(data, true);
    cJSON_Delete(j);
    if (out->parent == NULL || out->name == NULL) {
        task_data_free(out);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    return 0;
}

/* loadDiskTask: `type` picks the task, as upstream's switch on the name. */
static int load_disk_task(struct ks_taskloader *l, const char *type, const struct task_data *d,
                          char *err, size_t errlen)
{
    ks_debug("TaskMgr.loadDiskTask() %s, %s", type, d->name);
    struct ks_task *t = NULL;
    if (strcmp(type, KS_TASK_LOOPER) == 0) {
        /* taskConf.Data["interval"].(string): a panic upstream */
        const cJSON *iv = cJSON_GetObjectItemCaseSensitive(d->data, "interval");
        if (ks_task_assert(iv, "string", err, errlen) != NULL)
            return -1;
        t = ks_looper_new(d->name, iv->valuestring);
    } else if (strcmp(type, KS_TASK_DOWNLOADER) == 0) {
        t = ks_downloader_new(d->name, d->data);
        ks_info("LoadTaskData, downloader: %s", d->name);
    } else if (strcmp(type, KS_TASK_IOCSCANNER) == 0) {
        t = ks_iocscanner_new(d->name, d->data, err, errlen);
        if (t == NULL)
            return -1;
    } else {
        ks_debug("TaskStart, unknown task %s: %s", type, d->name);
        return 0;
    }
    if (t == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    char aerr[512];
    if (ks_taskmgr_add(l->mgr, t, aerr, sizeof(aerr)) < 0) {
        ks_error("loading task %s: %s", d->name, aerr);
        snprintf(err, errlen, "%s", aerr);
        return -1;
    }
    return 0;
}

/* loadDiskTasks */
static void load_disk_tasks(struct ks_taskloader *l)
{
    for (size_t i = 0; i < l->list.tasks.len; i++) {
        const struct task_config *task = KS_ARRAY_ITEM(l->list.tasks, struct task_config, i);
        struct task_data d;
        char err[1024];
        int ret = load_task_data(task->config_file, &d, err, sizeof(err));
        const char *inst = ret == 0 ? d.name : "";
        bool running = ks_taskmgr_get(l->mgr, inst) != NULL;
        if (!task->enabled) {
            ks_info("TaskMgr.loadDiskTasks() disabled: %s, %s", task->name, inst);
            remove_watch(l, task->config_file);
            char rerr[256];
            ks_taskmgr_remove(l->mgr, inst, rerr, sizeof(rerr));
        } else if (running) {
            ks_debug("TaskMgr.loadDiskTasks() %s already running, %s", task->name, inst);
        } else if (ret < 0) {
            ks_error("TaskMgr.LoadTaskFile() error loading %s: %s", task->config_file, err);
        } else if (load_disk_task(l, task->name, &d, err, sizeof(err)) < 0) {
            ks_error("TaskMgr.loadDiskTasks() loading task %s: %s", task->name, err);
        }
        if (ret == 0)
            task_data_free(&d);
    }
}

/* Loader.Load */
static int load_list(struct ks_taskloader *l, const char *path, char *err, size_t errlen)
{
    if (path == NULL || path[0] == '\0')
        path = KS_TASKS_DEFAULT_FILE;
    ks_debug("[tasks] Loader.Load() config file: %s", path);
    char e[512];
    size_t len = 0;
    char *raw = ks_read_file(path, TASKS_FILE_MAX, &len, e, sizeof(e));
    if (raw == NULL || len == 0) {
        /* an empty file: err is nil, which Go prints as %!s(<nil>) */
        snprintf(err, errlen, "error reading tasks list file %s: %s", path,
                 raw == NULL ? e : "%!s(<nil>)");
        free(raw);
        return -1;
    }
    struct tasks_list list;
    int ret = ks_schema_decode_buf(&tasks_list_schema, raw, len, &list, e, sizeof(e));
    free(raw);
    if (ret < 0) {
        snprintf(err, errlen, "Error unmarshalling config file %s: %s", path, e);
        return -1;
    }
    char *cfg = strdup(path);
    if (cfg == NULL) {
        ks_schema_free(&tasks_list_schema, &list);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    ks_schema_free(&tasks_list_schema, &l->list);
    l->list = list;
    free(l->cfg_file);
    l->cfg_file = cfg;
    if (!l->live && l->ifd >= 0) /* go l.liveReloadWorker() */
        l->live = true;
    return 0;
}

void ks_taskloader_load(struct ks_taskloader *l, const char *cfgfile)
{
    char err[1024];
    char *arg = xstrdup(cfgfile);
    if (arg != NULL) {
        free(l->reload_arg);
        l->reload_arg = arg;
    }
    if (load_list(l, cfgfile, err, sizeof(err)) < 0) {
        ks_warning("[tasks] LoadTaskFile, error loading tasks (%s), %s", cfgfile ? cfgfile : "",
                   err);
        return;
    }
    load_disk_tasks(l);
    add_watches(l);
}

void ks_taskloader_file_changed(struct ks_taskloader *l, const char *file)
{
    ks_info("[tasks] Task changed: %s", file);
    if (l->cfg_file != NULL && strcmp(file, l->cfg_file) == 0) {
        ks_info("[tasks] reloading tasks from %s", l->cfg_file);
        char *arg = xstrdup(l->reload_arg);
        ks_taskloader_load(l, arg);
        free(arg);
        return;
    }
    struct task_data d;
    char err[1024];
    if (load_task_data(file, &d, err, sizeof(err)) < 0) {
        ks_error("[tasks] LoadTaskFile() error loading %s: %s", file, err);
        return;
    }
    if (d.parent[0] == '\0') {
        free(d.parent);
        d.parent = xstrdup(d.name);
    }
    ks_info("[tasks] LoadTaskFile, task %s running", d.name);
    if (ks_taskmgr_remove(l->mgr, d.name, err, sizeof(err)) < 0)
        ks_error("[tasks] LoadTaskFile, error removing task %s: %s", d.name, err);
    /* upstream picks the task by its instance name here, not the list's
     * name: only instances named after their task restart */
    if (load_disk_task(l, d.name, &d, err, sizeof(err)) < 0)
        ks_error("[tasks] loading task %s: %s", d.name, err);
    task_data_free(&d);
}

const char *ks_taskloader_file(const struct ks_taskloader *l)
{
    return l->cfg_file != NULL ? l->cfg_file : "";
}

struct ks_taskloader *ks_taskloader_new(struct ks_taskmgr *m, struct ks_evloop *loop)
{
    struct ks_taskloader *l = calloc(1, sizeof(*l));
    if (l == NULL)
        return NULL;
    l->mgr = m;
    l->loop = loop;
    l->ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (l->ifd < 0) {
        ks_warning("NewTaskManager, unable to create the tasks loader: %s", strerror(errno));
    } else if (ks_evloop_add_fd(loop, l->ifd, EPOLLIN, on_inotify, l) < 0) {
        close(l->ifd);
        l->ifd = -1;
    }
    return l;
}

void ks_taskloader_free(struct ks_taskloader *l)
{
    if (l == NULL)
        return;
    while (l->pending != NULL)
        pending_free(l, l->pending);
    if (l->ifd >= 0) {
        ks_evloop_del_fd(l->loop, l->ifd);
        close(l->ifd);
    }
    for (size_t i = 0; i < l->nwatches; i++)
        free(l->watches[i].path);
    free(l->watches);
    ks_schema_free(&tasks_list_schema, &l->list);
    free(l->cfg_file);
    free(l->reload_arg);
    free(l);
}
