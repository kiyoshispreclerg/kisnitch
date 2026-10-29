/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/service.py (UIService): the RPC handlers
 * and the state behind the tray. Statistics, alerts and nodes go to the
 * database in phase 7; here they're logged.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/service.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/pb_util.h"
#include "ui/pyjson.h"
#include "ui/statsdb.h"
#include "ui/res.h"
#include "ui/i18n.h"

enum method { M_PING, M_ASK, M_SUBSCRIBE, M_NOTIFICATIONS, M_ALERT };

struct callctx {
    struct ks_service *svc;
    enum method m;
    char peer[KS_NODE_ADDR_MAX];
    struct ks_ask *ask; /* AskRule */
};

struct temp_rule {
    struct ks_service *svc;
    char node[KS_NODE_ADDR_MAX];
    char *name;
    guint source;
    struct temp_rule *next;
};

struct ks_service {
    struct ks_settings *settings;
    struct ks_service_ops ops;
    void *ud;
    struct ks_nodes nodes;
    struct ks_db *db;
    struct ks_rulesdb rules;
    struct ks_statsdb stats;
    struct ks_py_aliases aliases;
    struct ks_service_state st;
    bool version_warning_shown;
    bool exiting;
    struct ks_ask *active;        /* on screen */
    struct ks_ask *queue, *tail;  /* waiting */
    struct temp_rule *temp_rules; /* _sched_tasks */
    guint cleaner;                /* timeout of the database cleaner, 0 if none */
};

/* CleanerTask: every `interval` minutes, purge_oldest(max_days) */
static gboolean cleaner_tick(gpointer data)
{
    struct ks_service *svc = data;
    int days = ks_settings_get_int(svc->settings, KS_CFG_DB_MAX_DAYS, 1);
    ks_db_purge_oldest(svc->db, days);
    return G_SOURCE_CONTINUE;
}

static void stop_cleaner(struct ks_service *svc)
{
    if (svc->cleaner != 0)
        g_source_remove(svc->cleaner);
    svc->cleaner = 0;
}

static void start_cleaner(struct ks_service *svc)
{
    int interval = ks_settings_get_int(svc->settings, KS_CFG_DB_PURGE_INTERVAL, 5);
    if (interval < 1)
        interval = 1;
    svc->cleaner = g_timeout_add_seconds((guint)interval * 60, cleaner_tick, svc);
}

void ks_service_settings_saved(struct ks_service *svc)
{
    stop_cleaner(svc);
    if (ks_settings_get_bool(svc->settings, KS_CFG_DB_PURGE_OLDEST, false))
        start_cleaner(svc);
}

static const char *nz(const char *s)
{
    return s != NULL ? s : "";
}

/* ---- helpers ----------------------------------------------------------- */

long ks_ui_duration_seconds(const char *d)
{
    /* re.findall(r'(\d+)([smhdw]+)') */
    static const long second = 1, minute = 60, hour = 3600, day = 60 * 3600,
                      week = 60 * 60 * 3600;
    long secs = 0;
    const char *s = nz(d);
    while (*s) {
        if (!(*s >= '0' && *s <= '9')) {
            s++;
            continue;
        }
        long n = 0;
        while (*s >= '0' && *s <= '9') {
            if (n < 1000000000L)
                n = n * 10 + (*s - '0');
            s++;
        }
        const char *u = s;
        while (*s && strchr("smhdw", *s))
            s++;
        if (s - u != 1)
            continue; /* no unit, or "invalid unit" like "ms" */
        long unit = *u == 's' ? second : *u == 'm' ? minute : *u == 'h' ? hour
                    : *u == 'd' ? day : week;
        secs += unit * n;
    }
    return secs;
}

bool ks_ui_versions_differ(const char *ui, const char *daemon)
{
    unsigned lma, lmi, lpa, rma, rmi, rpa;
    char extra;
    if (sscanf(ui, "%u.%u.%u%c", &lma, &lmi, &lpa, &extra) != 3 ||
        sscanf(nz(daemon), "%u.%u.%u%c", &rma, &rmi, &rpa, &extra) != 3)
        return false; /* split(".") doesn't give 3 parts: an exception */
    return lma != rma || lmi != rmi;
}

static void reply_msg(struct ks_grpc_call *call, const ProtobufCMessage *m)
{
    size_t len;
    uint8_t *buf = ks_pb_pack(m, &len);
    if (buf == NULL) {
        ks_grpc_call_finish(call, KS_GRPC_UNKNOWN, "Exception serializing response!");
        return;
    }
    ks_grpc_call_send(call, buf, len);
    free(buf);
    ks_grpc_call_finish(call, KS_GRPC_OK, NULL);
}

static void status_changed(struct ks_service *svc)
{
    if (svc->ops.status_changed)
        svc->ops.status_changed(svc->ud);
}

static void message_u(struct ks_service *svc, const char *title, const char *body, int urgency)
{
    ks_info("[service] %s: %s", title, body);
    if (svc->ops.message)
        svc->ops.message(svc->ud, title, body, urgency);
}

static void message(struct ks_service *svc, const char *title, const char *body)
{
    message_u(svc, title, body, KS_URGENCY_NORMAL);
}

/* _update_fw_status() */
static void update_fw_status(struct ks_service *svc, bool enabled)
{
    svc->st.fw_enabled = enabled;
    status_changed(svc);
}

/* _set_daemon_connected() */
static void set_daemon_connected(struct ks_service *svc, bool connected)
{
    size_t n = ks_nodes_count(&svc->nodes);
    svc->st.connected = connected || n >= 1;
    svc->st.fw_menu_enabled = n == 1;
    if (!svc->st.connected)
        svc->st.fw_enabled = false;
    status_changed(svc);
}

/* ---- lifecycle --------------------------------------------------------- */

struct ks_service *ks_service_new(struct ks_settings *settings, const struct ks_service_ops *ops,
                                  void *ud)
{
    struct ks_service *svc = calloc(1, sizeof(*svc));
    if (svc == NULL)
        return NULL;
    svc->settings = settings;
    if (ops)
        svc->ops = *ops;
    svc->ud = ud;
    ks_nodes_init(&svc->nodes);
    ks_rulesdb_init(&svc->rules);

    /* Database.initialize() with the [database] settings */
    {
        char *file = ks_settings_get_string(settings, KS_CFG_DEFAULT_DB_FILE_KEY);
        bool mem = ks_settings_get_int(settings, KS_CFG_DEFAULT_DB_TYPE_KEY,
                                       KS_CFG_DB_TYPE_MEMORY) == KS_CFG_DB_TYPE_MEMORY;
        char err[256] = "";
        svc->db = ks_db_open(mem ? NULL : file,
                             ks_settings_get_bool(settings, KS_CFG_DEFAULT_DB_JRNL_WAL, false),
                             err, sizeof(err));
        if (svc->db == NULL) {
            ks_error("The DB is corrupted and it's not safe to continue. Remove, backup or "
                     "recover the file before continuing. %s",
                     err);
            free(file);
            ks_nodes_free(&svc->nodes);
            free(svc);
            return NULL;
        }
        free(file);
        if (!ks_rulesdb_attach(&svc->rules, svc->db))
            ks_warning("db: could not load the rules table");
        ks_statsdb_init(&svc->stats, svc->db, &svc->rules);
        ks_statsdb_reset_status(&svc->stats);
    }
    if (ks_py_aliases_parse(&svc->aliases, (const char *)ks_res_network_aliases_json,
                            ks_res_network_aliases_json_len) < 0)
        ks_warning("network aliases: invalid built-in network_aliases.json");
    bool ignore = ks_settings_get_bool(settings, KS_CFG_DEFAULT_IGNORE_RULES, false);
    ks_rulesdb_set_duration_filter(
        &svc->rules, ignore,
        ks_settings_get_int(settings, KS_CFG_DEFAULT_IGNORE_TEMPORARY_RULES, 0));
    if (ignore)
        ks_rulesdb_delete_filtered(&svc->rules);
    if (ks_settings_get_bool(settings, KS_CFG_DB_PURGE_OLDEST, false))
        start_cleaner(svc);
    return svc;
}

static void free_ask(struct ks_ask *ask)
{
    /* the call's on_close comes later and must not see it */
    if (ask->ctx != NULL)
        ((struct callctx *)ask->ctx)->ask = NULL;
    if (ask->con)
        protobuf_c_message_free_unpacked(&ask->con->base, NULL);
    free(ask);
}

void ks_service_free(struct ks_service *svc)
{
    if (svc == NULL)
        return;
    while (svc->temp_rules) {
        struct temp_rule *t = svc->temp_rules;
        svc->temp_rules = t->next;
        g_source_remove(t->source);
        free(t->name);
        free(t);
    }
    /* calls still open hold pointers to these */
    for (struct ks_ask *a = svc->queue; a != NULL;) {
        struct ks_ask *nx = a->next;
        free_ask(a);
        a = nx;
    }
    if (svc->active)
        free_ask(svc->active);
    ks_nodes_free(&svc->nodes);
    stop_cleaner(svc);
    ks_statsdb_free(&svc->stats);
    ks_rulesdb_free(&svc->rules);
    /* _on_close(): vacuum, optimize, close */
    ks_db_vacuum(svc->db);
    ks_db_optimize(svc->db);
    ks_db_close(svc->db);
    ks_py_aliases_free(&svc->aliases);
    free(svc);
}

struct ks_service_state ks_service_state(const struct ks_service *svc)
{
    return svc->st;
}

struct ks_nodes *ks_service_nodes(struct ks_service *svc)
{
    return &svc->nodes;
}

struct ks_db *ks_service_db(struct ks_service *svc)
{
    return svc->db;
}

struct ks_rulesdb *ks_service_rules(struct ks_service *svc)
{
    return &svc->rules;
}

const struct ks_py_aliases *ks_service_aliases(const struct ks_service *svc)
{
    return &svc->aliases;
}

struct ks_settings *ks_service_settings(struct ks_service *svc)
{
    return svc->settings;
}

/* ---- questions --------------------------------------------------------- */

static void next_question(struct ks_service *svc)
{
    while (svc->active == NULL && svc->queue != NULL) {
        struct ks_ask *a = svc->queue;
        svc->queue = a->next;
        if (svc->queue == NULL)
            svc->tail = NULL;
        a->next = NULL;
        svc->active = a;
        if (svc->ops.prompt) {
            svc->ops.prompt(svc->ud, a);
        } else {
            ks_service_answer(svc, a, NULL, false);
        }
    }
}

static gboolean temp_rule_expired(gpointer data)
{
    struct temp_rule *t = data;
    struct ks_service *svc = t->svc;
    /* _on_temp_rule_expired() */
    ks_rulesdb_disable(&svc->rules, t->node, t->name);
    for (struct temp_rule **pp = &svc->temp_rules; *pp; pp = &(*pp)->next) {
        if (*pp == t) {
            *pp = t->next;
            break;
        }
    }
    free(t->name);
    free(t);
    return G_SOURCE_REMOVE;
}

/* NODE_ACTIONS ADD_RULE: the answer goes to the rules table, and a
 * temporary one is disabled there when it expires. */
static void add_rule(struct ks_service *svc, const char *peer, const Protocol__Rule *rule)
{
    char node[KS_NODE_ADDR_MAX], now[32], created[32];
    ks_nodes_peer_addr(peer, node, sizeof(node));
    ks_db_date((int64_t)time(NULL), now, sizeof(now));
    ks_db_date(rule->created, created, sizeof(created));
    const Protocol__Operator *op = rule->operator_;
    const char *v[KS_RF_COUNT] = {
        [KS_RF_TIME] = now,
        [KS_RF_NODE] = node,
        [KS_RF_NAME] = rule->name,
        [KS_RF_ENABLED] = rule->enabled ? "True" : "False",
        [KS_RF_PRECEDENCE] = rule->precedence ? "True" : "False",
        [KS_RF_ACTION] = rule->action,
        [KS_RF_DURATION] = rule->duration,
        [KS_RF_OP_TYPE] = op ? op->type : "",
        [KS_RF_OP_SENSITIVE] = (op && op->sensitive) ? "True" : "False",
        [KS_RF_OP_OPERAND] = op ? op->operand : "",
        [KS_RF_OP_DATA] = op ? op->data : "",
        [KS_RF_DESCRIPTION] = rule->description,
        [KS_RF_NOLOG] = rule->nolog ? "True" : "False",
        [KS_RF_CREATED] = created,
    };
    ks_rulesdb_add_row(&svc->rules, v);

    long timeout = ks_ui_duration_seconds(rule->duration);
    if (strcmp(nz(rule->duration), "once") == 0)
        timeout = 1;
    if (timeout <= 0)
        return;
    struct temp_rule *t = calloc(1, sizeof(*t));
    if (t == NULL || (t->name = strdup(nz(rule->name))) == NULL) {
        free(t);
        return;
    }
    t->svc = svc;
    snprintf(t->node, sizeof(t->node), "%s", node);
    t->source = g_timeout_add_seconds((guint)(timeout > 1000000 ? 1000000 : timeout),
                                      temp_rule_expired, t);
    t->next = svc->temp_rules;
    svc->temp_rules = t;
}

void ks_service_answer(struct ks_service *svc, struct ks_ask *ask, Protocol__Rule *rule,
                       bool timeout_triggered)
{
    if (rule == NULL) {
        /* AskRule returns None: grpcio fails to serialize it */
        if (ask->call)
            ks_grpc_call_finish(ask->call, KS_GRPC_UNKNOWN, "Exception serializing response!");
    } else {
        if (timeout_triggered) {
            const Protocol__Connection *c = ask->con;
            char title[1024], body[4096], args[2048];
            if (nz(c->process_path)[0] != '\0')
                snprintf(title, sizeof(title), "%s", c->process_path);
            else
                snprintf(title, sizeof(title), "%s:%u (%s)",
                         nz(c->dst_host)[0] ? c->dst_host : nz(c->dst_ip), c->dst_port,
                         nz(c->protocol));
            size_t o = 0;
            args[0] = '\0';
            for (size_t i = 0; i < c->n_process_args && o < sizeof(args); i++) {
                int w = snprintf(args + o, sizeof(args) - o, "%s%s", i ? " " : "",
                                 nz(c->process_args[i]));
                if (w < 0)
                    break;
                o += (size_t)w;
            }
            char node_text[KS_NODE_ADDR_MAX + 16] = "";
            if (!ask->is_local)
                snprintf(node_text, sizeof(node_text), "on node %s", ask->node);
            snprintf(body, sizeof(body), "%s action applied %s\nCommand line: %s",
                     nz(rule->action), node_text, args);
            message(svc, title, body);
        }
        if (ks_rulesdb_duration_filtered(&svc->rules, rule->duration))
            ks_rulesdb_delete(&svc->rules, rule->name, ask->peer); /* sic: the raw peer */
        else
            add_rule(svc, ask->peer, rule);
        if (ask->call)
            reply_msg(ask->call, &rule->base);
    }
    if (svc->active == ask)
        svc->active = NULL;
    free_ask(ask);
    next_question(svc);
}

/* ---- RPCs -------------------------------------------------------------- */

static const char *node_name(const struct ks_node *n)
{
    return n != NULL && n->config != NULL ? nz(n->config->name) : "";
}

static const char *node_version(const struct ks_node *n)
{
    return n != NULL && n->config != NULL ? nz(n->config->version) : "";
}

static void on_subscribe(struct callctx *cc, struct ks_grpc_call *call, const uint8_t *msg,
                         size_t len)
{
    struct ks_service *svc = cc->svc;
    if (svc->exiting) {
        ks_grpc_call_cancel(call);
        return;
    }
    Protocol__ClientConfig *conf = (Protocol__ClientConfig *)ks_pb_unpack(
        &protocol__client_config__descriptor, msg, len);
    if (conf == NULL) {
        ks_grpc_call_finish(call, KS_GRPC_INTERNAL, "Exception deserializing request!");
        return;
    }
    ks_info("[Subscribe] %s", cc->peer);

    /* _overwrite_nodes_config(): our DefaultAction while connected */
    char *newconf = NULL;
    char err[128];
    cJSON *j = ks_json_parse(nz(conf->config), strlen(nz(conf->config)), err, sizeof(err));
    if (cJSON_IsObject(j)) {
        ks_settings_reload(svc->settings);
        int idx = ks_settings_get_int(svc->settings, KS_CFG_DEFAULT_ACTION_KEY, 0);
        const char *action = idx == KS_CFG_ACTION_ALLOW_IDX ? "allow" : "deny";
        cJSON *da = cJSON_CreateString(action);
        if (da != NULL) {
            if (cJSON_GetObjectItemCaseSensitive(j, "DefaultAction") != NULL)
                cJSON_ReplaceItemInObjectCaseSensitive(j, "DefaultAction", da);
            else
                cJSON_AddItemToObject(j, "DefaultAction", da);
        }
        ks_info("Setting daemon DefaultAction to: %s", action);
        newconf = ks_pyjson_dumps(j);
    } else {
        ks_warning("error parsing node's configuration: %s", err);
    }
    cJSON_Delete(j);

    Protocol__ClientConfig reply = *conf;
    if (newconf != NULL)
        reply.config = newconf;
    reply_msg(call, &reply.base);
    free(newconf);

    /* NODE_ADD */
    struct ks_node *node = ks_nodes_add(&svc->nodes, cc->peer, conf);
    if (node == NULL)
        return;
    ks_rulesdb_add_pb(&svc->rules, node->addr, node->config->rules, node->config->n_rules);
    ks_statsdb_node_insert(&svc->stats, node->addr, node_name(node), node_version(node),
                           KS_NODE_ONLINE);
    set_daemon_connected(svc, true);
    if (ks_nodes_count(&svc->nodes) <= 1)
        update_fw_status(svc, node->config->isfirewallrunning);
    else
        update_fw_status(svc, true);
    if (!ks_nodes_peer_is_unix(cc->peer)) {
        char body[KS_NODE_ADDR_MAX + 4];
        snprintf(body, sizeof(body), "(%s)", cc->peer);
        message(svc, _("New node connected"), body);
    }
}

static void on_ping(struct callctx *cc, struct ks_grpc_call *call, const uint8_t *msg,
                    size_t len)
{
    struct ks_service *svc = cc->svc;
    Protocol__PingRequest *p =
        (Protocol__PingRequest *)ks_pb_unpack(&protocol__ping_request__descriptor, msg, len);
    if (p == NULL) {
        ks_grpc_call_finish(call, KS_GRPC_INTERNAL, "Exception deserializing request!");
        return;
    }
    const char *dver = p->stats ? nz(p->stats->daemon_version) : "";
    if (ks_ui_versions_differ(KS_UPSTREAM_VERSION, dver) && !svc->version_warning_shown) {
        svc->version_warning_shown = true;
        if (svc->ops.version_warning)
            svc->ops.version_warning(svc->ud, dver, KS_UPSTREAM_VERSION);
    }
    char node[KS_NODE_ADDR_MAX];
    ks_nodes_peer_addr(cc->peer, node, sizeof(node));
    struct ks_node *n = ks_nodes_get(&svc->nodes, node);
    if (n != NULL)
        n->last_seen = time(NULL);
    if (p->stats != NULL && n != NULL) {
        /* _on_update_stats() -> _populate_stats() */
        struct ks_stats_refresh r = ks_statsdb_populate(&svc->stats, n->addr, node_name(n),
                                                         node_version(n), p->stats);
        if (svc->ops.stats_updated)
            svc->ops.stats_updated(svc->ud, p->stats, r.main || r.details);
    }
    if (p->stats)
        ks_debug("[Ping] %s: %llu connections, %llu rules, %zu events", node,
                 (unsigned long long)p->stats->connections, (unsigned long long)p->stats->rules,
                 p->stats->n_events);
    Protocol__PingReply r = PROTOCOL__PING_REPLY__INIT;
    r.id = p->id;
    protobuf_c_message_free_unpacked(&p->base, NULL);
    reply_msg(call, &r.base);
}

static void on_alert(struct callctx *cc, struct ks_grpc_call *call, const uint8_t *msg,
                     size_t len)
{
    struct ks_service *svc = cc->svc;
    Protocol__Alert *a = (Protocol__Alert *)ks_pb_unpack(&protocol__alert__descriptor, msg, len);
    if (a == NULL) {
        ks_grpc_call_finish(call, KS_GRPC_INTERNAL, "Exception deserializing request!");
        return;
    }
    /* _on_new_alert() */
    const char *text = a->data_case == PROTOCOL__ALERT__DATA_TEXT ? nz(a->text) : "";
    const char *path = (a->data_case == PROTOCOL__ALERT__DATA_PROC && a->proc)
                           ? nz(a->proc->path) : "";
    char body[4096];
    snprintf(body, sizeof(body), "%s", text);
    if (a->what == PROTOCOL__ALERT__WHAT__KERNEL_EVENT)
        snprintf(body, sizeof(body), "%s\n%s", text, path);
    if (!ks_nodes_peer_is_unix(cc->peer)) {
        char node[KS_NODE_ADDR_MAX];
        ks_nodes_peer_addr(cc->peer, node, sizeof(node));
        snprintf(body, sizeof(body), "node: %s\n\n%s\n%s", node, text, path);
    }
    if (a->action == PROTOCOL__ALERT__ACTION__SHOW_ALERT) {
        const char *title = _("Info");
        if (a->type == PROTOCOL__ALERT__TYPE__ERROR)
            title = _("Error");
        if (a->type == PROTOCOL__ALERT__TYPE__WARNING)
            title = _("Warning");
        /* the alert's priority is the notification's urgency */
        int urgency = KS_URGENCY_NORMAL;
        if (a->priority == PROTOCOL__ALERT__PRIORITY__LOW)
            urgency = KS_URGENCY_LOW;
        else if (a->priority == PROTOCOL__ALERT__PRIORITY__HIGH)
            urgency = KS_URGENCY_CRITICAL;
        message_u(svc, title, body, urgency);
        char node[KS_NODE_ADDR_MAX];
        ks_nodes_peer_addr(cc->peer, node, sizeof(node));
        ks_statsdb_alert(&svc->stats, node,
                         a->type == PROTOCOL__ALERT__TYPE__ERROR     ? "ERROR"
                         : a->type == PROTOCOL__ALERT__TYPE__WARNING ? "WARNING"
                                                                     : "INFO",
                         a->what == PROTOCOL__ALERT__WHAT__KERNEL_EVENT ? "KERNEL EVENT"
                                                                         : "GENERIC",
                         body);
    } else {
        ks_info("PostAlert() unknown alert action: %d", (int)a->action);
    }
    protobuf_c_message_free_unpacked(&a->base, NULL);
    Protocol__MsgResponse r = PROTOCOL__MSG_RESPONSE__INIT;
    r.id = 0;
    reply_msg(call, &r.base);
}

static void on_ask(struct callctx *cc, struct ks_grpc_call *call, const uint8_t *msg,
                   size_t len)
{
    struct ks_service *svc = cc->svc;
    if (cc->ask != NULL)
        return; /* one message per unary call */
    Protocol__Connection *con =
        (Protocol__Connection *)ks_pb_unpack(&protocol__connection__descriptor, msg, len);
    if (con == NULL) {
        ks_grpc_call_finish(call, KS_GRPC_INTERNAL, "Exception deserializing request!");
        return;
    }
    struct ks_ask *ask = calloc(1, sizeof(*ask));
    if (ask == NULL) {
        protobuf_c_message_free_unpacked(&con->base, NULL);
        ks_grpc_call_finish(call, KS_GRPC_UNKNOWN, "Exception serializing response!");
        return;
    }
    ask->svc = svc;
    ask->call = call;
    ask->con = con;
    snprintf(ask->peer, sizeof(ask->peer), "%s", cc->peer);
    ks_nodes_peer_addr(cc->peer, ask->node, sizeof(ask->node));
    ask->is_local = ks_nodes_peer_is_unix(cc->peer);
    cc->ask = ask;
    ask->ctx = cc;
    if (svc->tail)
        svc->tail->next = ask;
    else
        svc->queue = ask;
    svc->tail = ask;
    next_question(svc);
}

static void on_unary_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                             void *data)
{
    struct callctx *cc = data;
    switch (cc->m) {
    case M_SUBSCRIBE: on_subscribe(cc, call, msg, len); break;
    case M_PING: on_ping(cc, call, msg, len); break;
    case M_ALERT: on_alert(cc, call, msg, len); break;
    case M_ASK: on_ask(cc, call, msg, len); break;
    case M_NOTIFICATIONS: break;
    }
}

/* The question's call is over: the daemon gave up or we answered. */
static void forget_ask(struct ks_service *svc, struct ks_ask *ask)
{
    ask->call = NULL;
    ask->ctx = NULL;
    if (svc->active == ask)
        return; /* still on screen, as upstream: the answer goes nowhere */
    struct ks_ask **pp = &svc->queue, *prev = NULL;
    for (; *pp != NULL; prev = *pp, pp = &(*pp)->next) {
        if (*pp == ask) {
            *pp = ask->next;
            if (svc->tail == ask)
                svc->tail = prev;
            free_ask(ask);
            return;
        }
    }
}

static void on_unary_close(struct ks_grpc_call *call, int status, const char *msg, void *data)
{
    (void)call;
    struct callctx *cc = data;
    if (cc->m == M_ASK && cc->ask != NULL) {
        if (status != KS_GRPC_OK)
            ks_debug("[AskRule] %s: %s", cc->peer, msg);
        forget_ask(cc->svc, cc->ask);
    }
    free(cc);
}

/* Notifications: the daemon's replies to what we send. */
static void on_ntf_message(struct ks_grpc_call *call, const uint8_t *msg, size_t len,
                           void *data)
{
    (void)call;
    struct callctx *cc = data;
    Protocol__NotificationReply *r = (Protocol__NotificationReply *)ks_pb_unpack(
        &protocol__notification_reply__descriptor, msg, len);
    if (r == NULL)
        return;
    char node[KS_NODE_ADDR_MAX];
    ks_nodes_peer_addr(cc->peer, node, sizeof(node));
    if (r->code == PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR)
        ks_error("[service] notification reply error: %s %s", node, nz(r->data));
    ks_nodes_reply(&cc->svc->nodes, node, r);
    protobuf_c_message_free_unpacked(&r->base, NULL);
}

static void on_ntf_close(struct ks_grpc_call *call, int status, const char *msg, void *data)
{
    (void)status;
    (void)msg;
    struct callctx *cc = data;
    struct ks_service *svc = cc->svc;
    char node[KS_NODE_ADDR_MAX];
    ks_nodes_peer_addr(cc->peer, node, sizeof(node));
    struct ks_node *n = ks_nodes_get(&svc->nodes, node);
    if (n != NULL && n->stream == call) {
        /* _on_client_closed() */
        ks_info("[Notifications] client closed %s", cc->peer);
        n->stream = NULL;
        /* _delete_node() */
        ks_statsdb_node_forget(&svc->stats, n->addr);
        ks_statsdb_node_update(&svc->stats, n->addr, node_name(n), node_version(n),
                               KS_NODE_OFFLINE);
        ks_nodes_delete(&svc->nodes, cc->peer);
        if (svc->ops.stats_updated)
            svc->ops.stats_updated(svc->ud, NULL, true); /* _stats_dialog.update(True, None, True) */
        set_daemon_connected(svc, false);
        if (!ks_nodes_peer_is_unix(cc->peer)) {
            char body[KS_NODE_ADDR_MAX + 4];
            snprintf(body, sizeof(body), "(%s)", cc->peer);
            message(svc, _("node exited"), body);
        }
    }
    free(cc);
}

int ks_service_on_call(struct ks_service *svc, struct ks_grpc_call *call, const char *path,
                       const char *peer)
{
    static const struct {
        const char *path;
        enum method m;
    } methods[] = {
        {"/protocol.UI/Ping", M_PING},
        {"/protocol.UI/AskRule", M_ASK},
        {"/protocol.UI/Subscribe", M_SUBSCRIBE},
        {"/protocol.UI/Notifications", M_NOTIFICATIONS},
        {"/protocol.UI/PostAlert", M_ALERT},
    };
    struct callctx *cc = NULL;
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        if (strcmp(path, methods[i].path) != 0)
            continue;
        cc = calloc(1, sizeof(*cc));
        if (cc == NULL)
            return KS_GRPC_RESOURCE_EXHAUSTED;
        cc->svc = svc;
        cc->m = methods[i].m;
        snprintf(cc->peer, sizeof(cc->peer), "%s", peer);
        break;
    }
    if (cc == NULL)
        return KS_GRPC_UNIMPLEMENTED;

    if (cc->m != M_NOTIFICATIONS) {
        static const struct ks_grpc_call_cbs cbs = {.on_message = on_unary_message,
                                                    .on_close = on_unary_close};
        ks_grpc_call_set_cbs(call, &cbs, cc);
        return 0;
    }

    static const struct ks_grpc_call_cbs ncbs = {.on_message = on_ntf_message,
                                                 .on_close = on_ntf_close};
    ks_grpc_call_set_cbs(call, &ncbs, cc);
    char node[KS_NODE_ADDR_MAX];
    ks_nodes_peer_addr(peer, node, sizeof(node));
    struct ks_node *n = ks_nodes_get(&svc->nodes, node);
    ks_info("[Notifications] channel started: %s", peer);
    if (n == NULL || svc->exiting) {
        /* the generator returns right away */
        ks_grpc_call_finish(call, KS_GRPC_OK, NULL);
        return 0;
    }
    n->stream = call;
    ks_nodes_flush(n);
    return 0;
}

/* ---- tray actions ------------------------------------------------------ */

void ks_service_toggle_interception(struct ks_service *svc)
{
    bool enable = svc->st.fw_enabled; /* _enable_interception(self._fw_enabled) */
    if (!svc->st.connected)
        return;
    size_t n = ks_nodes_count(&svc->nodes);
    if (n == 0) {
        message(svc, _("No nodes connected"), "");
        return;
    }
    if (n > 1) {
        ks_info("enable interception for all nodes not supported yet");
        return;
    }
    Protocol__Notification ntf = PROTOCOL__NOTIFICATION__INIT;
    ntf.clientname = (char *)(uintptr_t) "";
    ntf.servername = (char *)(uintptr_t) "";
    ntf.data = (char *)(uintptr_t) "";
    ntf.type = enable ? PROTOCOL__ACTION__DISABLE_INTERCEPTION
                      : PROTOCOL__ACTION__ENABLE_INTERCEPTION;
    ks_nodes_send_all(&svc->nodes, &ntf, NULL, NULL);
    update_fw_status(svc, !enable);
}

void ks_service_node_delete(struct ks_service *svc, const char *addr)
{
    struct ks_node *n = ks_nodes_get(&svc->nodes, addr);
    if (n == NULL)
        return;
    /* the generator of its notifications ends, and with it the call; the
     * close path does the rest (_delete_node) */
    if (n->stream != NULL)
        ks_grpc_call_finish(n->stream, KS_GRPC_OK, NULL);
    else
        ks_nodes_delete(&svc->nodes, addr);
}

void ks_service_closing(struct ks_service *svc)
{
    svc->exiting = true;
    /* the questions get no rule */
    while (svc->queue) {
        struct ks_ask *a = svc->queue;
        svc->queue = a->next;
        if (a->call)
            ks_grpc_call_finish(a->call, KS_GRPC_UNKNOWN, "Exception serializing response!");
        free_ask(a);
    }
    svc->tail = NULL;
    /* stop_notifications(): every Notifications generator ends and
     * cancels its call */
    for (size_t i = 0; i < svc->nodes.len; i++) {
        struct ks_node *n = svc->nodes.items[i];
        if (n->stream != NULL) {
            struct ks_grpc_call *c = n->stream;
            n->stream = NULL;
            ks_grpc_call_cancel(c);
        }
    }
    /* update_all(Nodes.OFFLINE) */
    for (size_t i = 0; i < svc->nodes.len; i++) {
        const struct ks_node *n = svc->nodes.items[i];
        ks_statsdb_node_update(&svc->stats, n->addr, node_name(n), node_version(n),
                               KS_NODE_OFFLINE);
    }
}
