/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/tasks/socketsmonitor (main.go, dump.go,
 * options.go).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "cJSON.h"
#include "common/json_util.h"
#include "common/log.h"
#include "daemon/netstat.h"
#include "daemon/procmon/procmon.h"
#include "daemon/procmon/process.h"
#include "daemon/sockdiag.h"
#include "daemon/tasks/monitors.h"

#ifndef AF_XDP
#define AF_XDP 44
#endif

/* options: the protocol and family combinations that can be dumped. For
 * AF_PACKET the kernel refuses a protocol (EINVAL), so those two entries
 * never give sockets; the AF_PACKET sockets come from dumpPacketSockets. */
static const struct {
    uint8_t proto, fam;
} options[] = {
    {IPPROTO_DCCP, AF_INET},     {IPPROTO_DCCP, AF_INET6},    {IPPROTO_ICMPV6, AF_INET6},
    {IPPROTO_ICMP, AF_INET},     {IPPROTO_IGMP, AF_INET},     {IPPROTO_IGMP, AF_INET6},
    {IPPROTO_RAW, AF_INET},      {IPPROTO_RAW, AF_INET6},     {IPPROTO_SCTP, AF_INET},
    {IPPROTO_SCTP, AF_INET6},    {IPPROTO_TCP, AF_INET},      {IPPROTO_TCP, AF_INET6},
    {IPPROTO_UDP, AF_INET},      {IPPROTO_UDP, AF_INET6},     {IPPROTO_UDPLITE, AF_INET},
    {IPPROTO_UDPLITE, AF_INET6}, {IPPROTO_RAW, AF_PACKET},    {IPPROTO_UDP, AF_PACKET},
};

/* exclude(): 0 is AnySocket */
static bool exclude(uint8_t expected, uint8_t what)
{
    return expected > 0 && expected != what;
}

/* uint8(float64), as amd64 converts it: through int64, truncated */
static uint8_t to_u8(double v)
{
    if (!(v > -9.2e18 && v < 9.2e18))
        return 0;
    return (uint8_t)(uint64_t)(int64_t)v;
}

int ks_sockmon_config_parse(const cJSON *data, struct ks_sockmon_config *cfg, char *err,
                            size_t errlen)
{
    memset(cfg, 0, sizeof(*cfg));
    if (!cJSON_IsObject(data)) {
        /* upstream then crashes (SetID on the nil task) */
        char *txt = data ? cJSON_PrintUnformatted(data) : NULL;
        snprintf(err, errlen, "[sockmon] invalid config received: %s", txt ? txt : "<nil>");
        cJSON_free(txt);
        return -1;
    }
    /* cfg["interval"].(string) etc. panic upstream; their message here */
    const cJSON *iv = cJSON_GetObjectItem(data, "interval");
    const cJSON *st = cJSON_GetObjectItem(data, "state");
    const cJSON *pr = cJSON_GetObjectItem(data, "proto");
    const cJSON *fa = cJSON_GetObjectItem(data, "family");
    if (ks_task_assert(iv, "string", err, errlen) || ks_task_assert(st, "float64", err, errlen) ||
        ks_task_assert(pr, "float64", err, errlen) || ks_task_assert(fa, "float64", err, errlen))
        return -1;
    snprintf(cfg->interval, sizeof(cfg->interval), "%s",
             iv->valuestring[0] != '\0' ? iv->valuestring : "5s");
    cfg->state = to_u8(st->valuedouble);
    cfg->proto = to_u8(pr->valuedouble);
    cfg->family = to_u8(fa->valuedouble);
    return 0;
}

/* ---- the table -------------------------------------------------------- */

/* A netlink.Socket; `ips` false for the AF_PACKET and AF_XDP ones, whose
 * addresses are nil. */
struct row {
    struct ks_sock s;
    bool ips;
    int pid;
    uint16_t proto;
};

struct table {
    cJSON *rows;  /* Table */
    cJSON *procs; /* Processes, keyed by the PID as a string */
    bool oom;
};

static cJSON *ip_json(const struct ks_ip *ip, bool present)
{
    char buf[64] = "";
    if (present)
        ks_ip_string(ip, buf, sizeof(buf));
    return cJSON_CreateString(buf);
}

static cJSON *socket_json(const struct ks_sock *s, bool ips)
{
    cJSON *o = cJSON_CreateObject(), *id = cJSON_CreateObject(), *ck = cJSON_CreateArray();
    bool ok = o != NULL && id != NULL && ck != NULL;
    for (int i = 0; ok && i < 2; i++) {
        char b[16];
        snprintf(b, sizeof(b), "%u", s->cookie[i]);
        cJSON *c = cJSON_CreateRaw(b);
        ok = c != NULL && cJSON_AddItemToArray(ck, c);
        if (!ok)
            cJSON_Delete(c);
    }
    ok = ok && cJSON_AddItemToObject(id, "Source", ip_json(&s->src, ips)) &&
         cJSON_AddItemToObject(id, "Destination", ip_json(&s->dst, ips)) &&
         cJSON_AddItemToObject(id, "Cookie", ck);
    if (!ok)
        cJSON_Delete(ck);
    ok = ok && ks_json_add_uint(id, "Interface", s->iface) &&
         ks_json_add_uint(id, "SourcePort", s->sport) &&
         ks_json_add_uint(id, "DestinationPort", s->dport);
    if (ok && !cJSON_AddItemToObject(o, "ID", id))
        ok = false;
    else if (!ok)
        cJSON_Delete(id);
    ok = ok && ks_json_add_uint(o, "Expires", s->expires) &&
         ks_json_add_uint(o, "RQueue", s->rqueue) && ks_json_add_uint(o, "WQueue", s->wqueue) &&
         ks_json_add_uint(o, "UID", s->uid) && ks_json_add_uint(o, "INode", s->inode) &&
         ks_json_add_uint(o, "Family", s->family) && ks_json_add_uint(o, "State", s->state) &&
         ks_json_add_uint(o, "Timer", s->timer) && ks_json_add_uint(o, "Retrans", s->retrans);
    if (!ok) {
        cJSON_Delete(o);
        return NULL;
    }
    return o;
}

/* addSocketToTable */
static void add_socket(struct table *t, const struct ks_sock *s, bool ips, uint16_t proto)
{
    char src[64], dst[64], key[192];
    if (ips) {
        ks_ip_string(&s->src, src, sizeof(src));
        ks_ip_string(&s->dst, dst, sizeof(dst));
    } else {
        snprintf(src, sizeof(src), "<nil>");
        snprintf(dst, sizeof(dst), "<nil>");
    }
    snprintf(key, sizeof(key), "%u %s %u %s %u", s->inode, src, (unsigned)s->sport, dst,
             (unsigned)s->dport);
    int pid = ks_procmon_pid_from_inode((int64_t)s->inode, key);

    /* pid -1 (e.g. a tor socket in FIN_WAIT1): an empty Process{} */
    char pidkey[16];
    snprintf(pidkey, sizeof(pidkey), "%d", pid);
    if (!cJSON_HasObjectItem(t->procs, pidkey)) {
        cJSON *pj;
        if (pid == -1) {
            pj = ks_proc_zero_cjson();
        } else {
            struct ks_proc *p = ks_procmon_find_process(pid, false);
            pj = p != NULL ? ks_proc_to_cjson(p) : cJSON_CreateNull();
            ks_proc_unref(p);
        }
        if (pj == NULL || !cJSON_AddItemToObject(t->procs, pidkey, pj)) {
            cJSON_Delete(pj);
            t->oom = true;
            return;
        }
    }

    char ifname[IF_NAMESIZE + 1] = "";
    if (s->iface == 0 || if_indextoname(s->iface, ifname) == NULL)
        ifname[0] = '\0';
    cJSON *row = cJSON_CreateObject();
    cJSON *sj = socket_json(s, ips);
    bool ok = row != NULL && sj != NULL && cJSON_AddItemToObject(row, "Socket", sj);
    if (!ok)
        cJSON_Delete(sj);
    ok = ok && cJSON_AddStringToObject(row, "Iface", ifname) && ks_json_add_int(row, "PID", pid) &&
         ks_json_add_uint(row, "Mark", 0) && ks_json_add_uint(row, "Proto", proto) &&
         cJSON_AddItemToArray(t->rows, row);
    if (!ok) {
        cJSON_Delete(row);
        t->oom = true;
    }
}

static void dump_xdp(const struct ks_sockmon_config *cfg, struct table *t)
{
    if (exclude(cfg->family, AF_XDP) && exclude(cfg->proto, IPPROTO_RAW))
        return;
    struct ks_xdp_sock *v;
    size_t n;
    char err[256];
    if (ks_sock_dump_xdp(&v, &n, err, sizeof(err)) < 0)
        return;
    for (size_t i = 0; i < n; i++) {
        struct ks_sock s;
        memset(&s, 0, sizeof(s));
        s.family = AF_XDP;
        s.inode = v[i].inode;
        s.uid = v[i].uid;
        s.iface = v[i].ifindex;
        s.cookie[0] = v[i].cookie[0];
        s.cookie[1] = v[i].cookie[1];
        add_socket(t, &s, false, IPPROTO_RAW);
    }
    free(v);
}

static void dump_packet(const struct ks_sockmon_config *cfg, struct table *t)
{
    if (exclude(cfg->family, AF_PACKET))
        return;
    struct ks_packet_sock *v;
    size_t n;
    char err[256];
    if (ks_sock_dump_packet(&v, &n, err, sizeof(err)) == 0) {
        for (size_t i = 0; i < n; i++) {
            struct ks_sock s;
            memset(&s, 0, sizeof(s));
            s.family = AF_PACKET;
            s.inode = v[i].inode;
            s.uid = v[i].uid;
            s.iface = v[i].index;
            s.cookie[0] = v[i].cookie[0];
            s.cookie[1] = v[i].cookie[1];
            add_socket(t, &s, false, v[i].num);
        }
        free(v);
        return;
    }
    /* the kernel dump failed: /proc/net/packet */
    struct ks_netstat_entry *e;
    if (ks_netstat_parse_packet(&e, &n) < 0)
        return;
    for (size_t i = 0; i < n; i++) {
        struct ks_sock s;
        memset(&s, 0, sizeof(s));
        s.family = AF_PACKET;
        s.inode = (uint32_t)e[i].inode;
        s.uid = (uint32_t)e[i].uid;
        s.iface = (uint32_t)e[i].iface;
        add_socket(t, &s, false, IPPROTO_RAW);
    }
    free(e);
}

char *ks_sockmon_dump_json(const struct ks_sockmon_config *cfg)
{
    struct table t = {cJSON_CreateArray(), cJSON_CreateObject(), false};
    if (t.rows == NULL || t.procs == NULL) {
        cJSON_Delete(t.rows);
        cJSON_Delete(t.procs);
        return NULL;
    }
    for (size_t o = 0; o < sizeof(options) / sizeof(options[0]) && !t.oom; o++) {
        if (exclude(cfg->family, options[o].fam) || exclude(cfg->proto, options[o].proto))
            continue;
        struct ks_sock *socks;
        size_t n;
        char err[256];
        if (ks_sock_dump(options[o].fam, options[o].proto, &socks, &n, err, sizeof(err)) < 0) {
            ks_debug("[sockmon][%zu] fam: %u, proto: %u, error: %s", o,
                     (unsigned)options[o].fam, (unsigned)options[o].proto, err);
            continue;
        }
        for (size_t i = 0; i < n && !t.oom; i++)
            if (!exclude(cfg->state, socks[i].state))
                add_socket(&t, &socks[i], true, options[o].proto);
        free(socks);
    }
    if (!t.oom)
        dump_xdp(cfg, &t);
    if (!t.oom)
        dump_packet(cfg, &t);

    /* Processes is a map[int]: json.Marshal sorts its keys as strings */
    cJSON *sorted = cJSON_CreateObject();
    cJSON *root = cJSON_CreateObject();
    char *out = NULL;
    if (!t.oom && sorted != NULL && root != NULL) {
        size_t np = (size_t)cJSON_GetArraySize(t.procs);
        cJSON **items = np ? malloc(np * sizeof(*items)) : NULL;
        if (np == 0 || items != NULL) {
            size_t k = 0;
            for (cJSON *c = t.procs->child; c != NULL; c = c->next)
                items[k++] = c;
            for (size_t i = 1; i < np; i++)
                for (size_t j = i; j > 0 && strcmp(items[j - 1]->string, items[j]->string) > 0;
                     j--) {
                    cJSON *x = items[j];
                    items[j] = items[j - 1];
                    items[j - 1] = x;
                }
            for (size_t i = 0; i < np; i++) {
                cJSON *c = cJSON_DetachItemViaPointer(t.procs, items[i]);
                cJSON_AddItemToObject(sorted, c->string, c);
            }
            free(items);
            cJSON_AddItemToObject(root, "Table", t.rows);
            t.rows = NULL;
            cJSON_AddItemToObject(root, "Processes", sorted);
            sorted = NULL;
            out = ks_json_print_go(root, false);
        }
    }
    cJSON_Delete(t.rows);
    cJSON_Delete(t.procs);
    cJSON_Delete(sorted);
    cJSON_Delete(root);
    return out;
}

/* ---- the task --------------------------------------------------------- */

static int sockmon_start(struct ks_task *t, char *err, size_t errlen)
{
    const struct ks_sockmon_config *cfg = t->priv;
    return ks_task_parse_interval(cfg->interval, &t->interval_ns, err, errlen);
}

static enum ks_task_status sockmon_run(struct ks_task *t, char **data, char *err,
                                       size_t errlen)
{
    *data = ks_sockmon_dump_json(t->priv);
    if (*data == NULL) {
        snprintf(err, errlen, "out of memory");
        return KS_TASK_ERROR;
    }
    return KS_TASK_RESULT;
}

static void sockmon_free(void *priv)
{
    if (priv != NULL)
        ks_debug("[tasks.SocketsMonitor] stopped");
    free(priv);
}

static const struct ks_task_ops sockmon_ops = {sockmon_start, sockmon_run, sockmon_free};

struct ks_task *ks_sockmon_new(const struct ks_sockmon_config *cfg, bool temporary)
{
    struct ks_sockmon_config *c = malloc(sizeof(*c));
    if (c == NULL)
        return NULL;
    *c = *cfg;
    struct ks_task *t = ks_task_new(KS_TASK_SOCKETS_MONITOR, &sockmon_ops, c);
    if (t != NULL)
        t->temporary = temporary;
    return t;
}
