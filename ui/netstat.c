/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See netstat.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/netstat.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/json_util.h"
#include "ui/pyjson.h"

struct name {
    const char *num, *name;
};

static const struct name families[] = {
    {"0", "AF_UNSPEC"}, {"2", "AF_INET"},  {"10", "AF_INET6"}, {"17", "AF_PACKET"},
    {"40", "AF_VSOCK"}, {"44", "AF_XDP"}, {"45", "AF_MCTP"},   {NULL, NULL}};

static const struct name protos[] = {
    {"0", "IP"},         {"1", "ICMP"},         {"2", "IGMP"},         {"6", "TCP"},
    {"17", "UDP"},       {"33", "DCCP"},        {"41", "IPv6"},        {"58", "ICMPv6"},
    {"132", "SCTP"},     {"136", "UDPLITE"},    {"255", "RAW"},        {"3", "ETH_P_ALL"},
    {"2048", "ETH_P_IP"}, {"34525", "ETH_P_IPV6"}, {"2054", "ETH_P_ARP"}, {"32821", "ETH_P_RARP"},
    {"33024", "ETH_P_8021Q"}, {"4", "ETH_P_802_2"}, {"34916", "ETH_P_PPPOE"},
    {"34958", "ETH_P_PAE"}, {"35085", "ETH_P_FCOE"}, {NULL, NULL}};

static const struct name states[] = {
    {"0", "LISTEN"},         {"1", "Established"},   {"2", "TCP_SYN_SENT"},
    {"3", "TCP_SYN_RECV"},   {"4", "TCP_FIN_WAIT1"}, {"5", "TCP_FIN_WAIT2"},
    {"6", "TCP_TIME_WAIT"},  {"7", "CLOSE"},         {"8", "TCP_CLOSE_WAIT"},
    {"9", "TCP_LAST_ACK"},   {"10", "LISTEN"},       {"11", "TCP_CLOSING"},
    {"12", "TCP_NEW_SYNC_RECV"}, {"13", "TCP_MAX_STATES"}, {NULL, NULL}};

static const char *lookup(const struct name *t, const char *n)
{
    for (; t->num != NULL; t++) {
        if (strcmp(t->num, n) == 0)
            return t->name;
    }
    return NULL;
}

const char *ks_sockets_state(const char *n)
{
    return lookup(states, n);
}

const char *ks_sockets_proto(const char *n)
{
    return lookup(protos, n);
}

const char *ks_sockets_family(const char *n)
{
    return lookup(families, n);
}

const char *ks_netstat_display(int col, const char *text)
{
    const char *r = NULL;
    switch (col) {
    case 2: r = ks_sockets_state(text); break;
    case 7: r = ks_sockets_proto(text); break;
    case 10: r = ks_sockets_family(text); break;
    default: return text;
    }
    /* the KeyError of upstream: the cell comes out empty */
    return r != NULL ? r : "";
}

/* ---- the JSON ----------------------------------------------------------- */

static const cJSON *need(const cJSON *o, const char *k, char *err, size_t n)
{
    const cJSON *v = cJSON_IsObject(o) ? cJSON_GetObjectItemCaseSensitive(o, k) : NULL;
    if (v == NULL)
        snprintf(err, n, "KeyError('%s')", k);
    return v;
}

/* a value as the text Python's str() gives and SQLite stores: ints, strings,
 * a list as "[1, 2]"; null is NULL */
static char *as_text(const cJSON *v)
{
    if (v == NULL || cJSON_IsNull(v))
        return NULL;
    if (cJSON_IsString(v))
        return g_strdup(v->valuestring);
    if (cJSON_IsBool(v))
        return g_strdup(cJSON_IsTrue(v) ? "True" : "False");
    if (cJSON_IsNumber(v)) {
        char *s = ks_pyjson_dumps(v);
        char *r = s != NULL ? g_strdup(s) : NULL;
        free(s);
        return r;
    }
    if (cJSON_IsArray(v)) {
        GString *g = g_string_new("[");
        const cJSON *it;
        cJSON_ArrayForEach(it, v)
        {
            char *t = as_text(it);
            g_string_append_printf(g, "%s%s", it == v->child ? "" : ", ", t != NULL ? t : "None");
            g_free(t);
        }
        g_string_append_c(g, ']');
        return g_string_free(g, FALSE);
    }
    char *s = ks_pyjson_dumps(v);
    char *r = s != NULL ? g_strdup(s) : NULL;
    free(s);
    return r;
}

int ks_netstat_update(struct ks_db *db, const char *node, const char *json, char *err,
                      size_t errlen)
{
    cJSON *j = ks_json_parse(json, strlen(json), err, errlen);
    if (!cJSON_IsObject(j)) {
        cJSON_Delete(j);
        if (err[0] == '\0')
            snprintf(err, errlen, "%s", "not a JSON object");
        return -1;
    }
    const cJSON *table = need(j, "Table", err, errlen);
    const cJSON *procs = table ? need(j, "Processes", err, errlen) : NULL;
    if (table == NULL || procs == NULL || !cJSON_IsArray(table)) {
        if (table != NULL && procs != NULL)
            snprintf(err, errlen, "%s", "TypeError: 'NoneType' object is not iterable");
        cJSON_Delete(j);
        return -1;
    }
    char now[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(now, sizeof(now), "%Y-%m-%d %H:%M:%S", &tm);

    /* TODO upstream: make this optional */
    ks_db_clean(db, "sockets");
    ks_db_exec(db, "BEGIN");
    int count = 0;
    const cJSON *k;
    cJSON_ArrayForEach(k, table)
    {
        if (cJSON_IsNull(k))
            continue;
        const cJSON *sck = need(k, "Socket", err, errlen);
        const cJSON *id = sck ? need(sck, "ID", err, errlen) : NULL;
        const cJSON *kiface = id ? need(k, "Iface", err, errlen) : NULL;
        const cJSON *kpid = kiface ? need(k, "PID", err, errlen) : NULL;
        const cJSON *proto = kpid ? need(k, "Proto", err, errlen) : NULL;
        const cJSON *f[17] = {NULL};
        static const char *const idk[] = {"SourcePort", "Source", "Destination", "DestinationPort",
                                          "Interface", "Cookie"};
        static const char *const sk[] = {"UID", "INode", "Family", "State", "RQueue", "WQueue",
                                         "Expires", "Retrans", "Timer"};
        bool ok = proto != NULL;
        for (int i = 0; ok && i < 6; i++)
            ok = (f[i] = need(id, idk[i], err, errlen)) != NULL;
        for (int i = 0; ok && i < 9; i++)
            ok = (f[6 + i] = need(sck, sk[i], err, errlen)) != NULL;
        if (!ok) {
            ks_db_exec(db, "ROLLBACK");
            cJSON_Delete(j);
            return -1;
        }
        char *iface = as_text(f[4]);
        if (cJSON_IsString(kiface) && kiface->valuestring[0] != '\0') {
            g_free(iface);
            iface = g_strdup(kiface->valuestring);
        }
        char *pid_s = NULL, *path = g_strdup(""), *comm = g_strdup("");
        if (cJSON_IsNumber(kpid) && (long)kpid->valuedouble != -1) {
            char key[32];
            snprintf(key, sizeof(key), "%ld", (long)kpid->valuedouble);
            const cJSON *p = cJSON_GetObjectItemCaseSensitive(procs, key);
            if (p != NULL) {
                pid_s = g_strdup(key);
                const cJSON *pp = need(p, "Path", err, errlen);
                const cJSON *pc = pp ? need(p, "Comm", err, errlen) : NULL;
                if (pc == NULL) {
                    ks_db_exec(db, "ROLLBACK");
                    g_free(iface);
                    g_free(pid_s);
                    g_free(path);
                    g_free(comm);
                    cJSON_Delete(j);
                    return -1;
                }
                g_free(path);
                g_free(comm);
                path = as_text(pp);
                comm = as_text(pc);
            }
        }
        /* (last_seen, node, src_port, src_ip, dst_ip, dst_port, proto, uid, inode, iface,
         *  family, state, cookies, rqueue, wqueue, expires, retrans, timer, proc_path,
         *  proc_comm, proc_pid) */
        char *v[21];
        v[0] = g_strdup(now);
        v[1] = g_strdup(node);
        v[2] = as_text(f[0]);
        v[3] = as_text(f[1]);
        v[4] = as_text(f[2]);
        v[5] = as_text(f[3]);
        v[6] = as_text(proto);
        v[7] = as_text(f[6]);
        v[8] = as_text(f[7]);
        v[9] = iface;
        v[10] = as_text(f[8]);
        v[11] = as_text(f[9]);
        v[12] = as_text(f[5]);
        v[13] = as_text(f[10]);
        v[14] = as_text(f[11]);
        v[15] = as_text(f[12]);
        v[16] = as_text(f[13]);
        v[17] = as_text(f[14]);
        v[18] = path;
        v[19] = comm;
        v[20] = pid_s != NULL ? pid_s : g_strdup("");
        /* a null (the IP of a packet socket) is stored as NULL */
        sqlite3_stmt *st;
        sqlite3 *h = ks_db_handle(db);
        if (sqlite3_prepare_v2(
                h,
                "INSERT OR REPLACE INTO sockets (last_seen, node, src_port, src_ip, dst_ip, "
                "dst_port, proto, uid, inode, iface, family, state, cookies, rqueue, wqueue, "
                "expires, retrans, timer, proc_path, proc_comm, proc_pid) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                -1, &st, NULL) == SQLITE_OK) {
            for (int i = 0; i < 21; i++) {
                if (v[i] != NULL)
                    sqlite3_bind_text(st, i + 1, v[i], -1, SQLITE_TRANSIENT);
                else
                    sqlite3_bind_null(st, i + 1);
            }
            if (sqlite3_step(st) == SQLITE_DONE)
                count++;
            sqlite3_finalize(st);
        }
        for (int i = 0; i < 21; i++)
            g_free(v[i]);
    }
    ks_db_exec(db, "COMMIT");
    cJSON_Delete(j);
    return count;
}
