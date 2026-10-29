/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream ui/opensnitch/nodes.py (the parts the pop-up, the tray
 * and the protocol need; the database and the firewall parts come with
 * phases 7 and 8).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
/* struct ifreq and SIOCGIFCONF are not POSIX */
#define _DEFAULT_SOURCE 1
#include "ui/nodes.h"

#include "common/arena.h"
#include "common/sysfw.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "common/pb_util.h"
#include "ui/pyjson.h"

void ks_nodes_init(struct ks_nodes *n)
{
    memset(n, 0, sizeof(*n));
}

static void free_node(struct ks_node *node)
{
    if (node->config)
        protobuf_c_message_free_unpacked(&node->config->base, NULL);
    if (node->fw != NULL) {
        ks_sysfw_free(node->fw);
        free(node->fw);
    }
    for (size_t i = 0; i < node->nqueue; i++)
        free(node->queue[i].buf);
    free(node->queue);
    free(node);
}

void ks_nodes_free(struct ks_nodes *n)
{
    for (size_t i = 0; i < n->len; i++)
        free_node(n->items[i]);
    free(n->items);
    free(n->sent);
    memset(n, 0, sizeof(*n));
}

void ks_nodes_peer_addr(const char *peer, char *out, size_t len)
{
    /* peer.split(":")[0], [1] */
    const char *c1 = strchr(peer, ':');
    if (c1 == NULL) {
        /* upstream returns the whole peer here (and fails later) */
        snprintf(out, len, "%s", peer);
        return;
    }
    const char *a = c1 + 1, *c2 = strchr(a, ':');
    size_t al = c2 ? (size_t)(c2 - a) : strlen(a);
    int pl = (int)(c1 - peer);
    /* WA for backward compatibility: "unix:" -> "unix:/local" */
    if (pl == 4 && strncmp(peer, "unix", 4) == 0 && al == 0)
        snprintf(out, len, "unix:/local");
    else
        snprintf(out, len, "%.*s:%.*s", pl, peer, (int)al, a);
}

size_t ks_net_ifaces(struct ks_iface *out, size_t max)
{
    /* NetworkInterfaces.list(): SIOCGIFCONF on a datagram socket, IPv4 only */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    struct ifreq buf[64];
    struct ifconf ifc;
    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_len = (int)sizeof(buf);
    ifc.ifc_req = buf;
    size_t n = 0;
    if (ioctl(fd, SIOCGIFCONF, &ifc) == 0) {
        size_t cnt = (size_t)ifc.ifc_len / sizeof(struct ifreq);
        for (size_t i = 0; i < cnt && n < max; i++) {
            struct sockaddr_in sin;
            memcpy(&sin, &buf[i].ifr_addr, sizeof(sin));
            snprintf(out[n].name, sizeof(out[n].name), "%.*s", (int)IFNAMSIZ - 1, buf[i].ifr_name);
            if (inet_ntop(AF_INET, &sin.sin_addr, out[n].ip, sizeof(out[n].ip)) != NULL)
                n++;
        }
    }
    close(fd);
    return n;
}

bool ks_nodes_is_local(const char *addr)
{
    if (strncmp(addr, "unix", 4) == 0)
        return true;
    if (strncmp(addr, "ipv4", 4) == 0 || strncmp(addr, "ipv6", 4) == 0) {
        struct ks_iface ifs[64];
        size_t n = ks_net_ifaces(ifs, 64);
        for (size_t i = 0; i < n; i++) {
            if (strstr(addr, ifs[i].ip) != NULL)
                return true;
        }
    }
    return false;
}

bool ks_nodes_peer_is_unix(const char *peer)
{
    return strncmp(peer, "unix:", 5) == 0 || strncmp(peer, "unix-abstract:", 14) == 0;
}

struct ks_node *ks_nodes_get(const struct ks_nodes *n, const char *addr)
{
    for (size_t i = 0; i < n->len; i++) {
        if (strcmp(n->items[i]->addr, addr) == 0)
            return n->items[i];
    }
    return NULL;
}

size_t ks_nodes_count(const struct ks_nodes *n)
{
    return n->len;
}

const char *ks_nodes_hostname(const struct ks_nodes *n, const char *addr)
{
    const struct ks_node *node = ks_nodes_get(n, addr);
    if (node == NULL || node->config == NULL || node->config->name == NULL)
        return "";
    return node->config->name;
}

/* get_client_config(): a config without LogLevel gets "LogLevel": 1. */
static void fix_log_level(Protocol__ClientConfig *cc)
{
    char err[128];
    if (cc->config == NULL)
        return;
    cJSON *j = ks_json_parse(cc->config, strlen(cc->config), err, sizeof(err));
    if (j == NULL) {
        ks_warning("[Nodes]: exception parsing client config %s", err);
        return;
    }
    if (cJSON_IsObject(j) && cJSON_GetObjectItemCaseSensitive(j, "LogLevel") == NULL) {
        cJSON_AddNumberToObject(j, "LogLevel", 1);
        char *s = ks_pyjson_dumps(j);
        if (s != NULL) {
            /* the message was unpacked with the default allocator */
            free(cc->config);
            cc->config = s;
        }
    }
    cJSON_Delete(j);
}

struct ks_node *ks_nodes_add(struct ks_nodes *n, const char *peer,
                             Protocol__ClientConfig *config)
{
    char addr[KS_NODE_ADDR_MAX];
    ks_nodes_peer_addr(peer, addr, sizeof(addr));
    struct ks_node *node = ks_nodes_get(n, addr);
    if (node == NULL) {
        if (n->len == n->cap) {
            size_t ncap = n->cap ? n->cap * 2 : 4;
            struct ks_node **ni = realloc(n->items, ncap * sizeof(*ni));
            if (ni == NULL)
                goto fail;
            n->items = ni;
            n->cap = ncap;
        }
        node = calloc(1, sizeof(*node));
        if (node == NULL)
            goto fail;
        snprintf(node->addr, sizeof(node->addr), "%s", addr);
        n->items[n->len++] = node;
    }
    node->last_seen = time(NULL);
    node->online = true;
    if (config != NULL) {
        fix_log_level(config);
        if (node->config)
            protobuf_c_message_free_unpacked(&node->config->base, NULL);
        node->config = config;
        /* add_fw_config(addr, client_config.systemFirewall) */
        if (node->fw != NULL) {
            ks_sysfw_free(node->fw);
            free(node->fw);
            node->fw = NULL;
        }
        if (config->systemfirewall != NULL && (node->fw = calloc(1, sizeof(*node->fw))) != NULL &&
            ks_sysfw_from_pb(node->fw, config->systemfirewall) < 0) {
            free(node->fw);
            node->fw = NULL;
        }
    }
    return node;
fail:
    if (config)
        protobuf_c_message_free_unpacked(&config->base, NULL);
    return NULL;
}

void ks_nodes_delete(struct ks_nodes *n, const char *peer)
{
    char addr[KS_NODE_ADDR_MAX];
    ks_nodes_peer_addr(peer, addr, sizeof(addr));
    for (size_t i = 0; i < n->len; i++) {
        if (strcmp(n->items[i]->addr, addr) == 0) {
            free_node(n->items[i]);
            memmove(&n->items[i], &n->items[i + 1], (n->len - i - 1) * sizeof(n->items[0]));
            n->len--;
            return;
        }
    }
}

uint64_t ks_nodes_new_id(struct ks_nodes *n)
{
    /* str(time.time()) is the shortest repr of the float, so the digits
     * after the dot vary; what matters is that ids grow */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double t = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
    char buf[40], digits[40];
    for (int p = 1; p <= 17; p++) {
        snprintf(buf, sizeof(buf), "%.*g", p, t);
        if (strtod(buf, NULL) == t)
            break;
    }
    size_t o = 0;
    for (const char *s = buf; *s && o + 1 < sizeof(digits); s++) {
        if (*s >= '0' && *s <= '9')
            digits[o++] = *s;
    }
    digits[o] = '\0';
    uint64_t id = strtoull(digits, NULL, 10);
    if (id <= n->last_id)
        id = n->last_id + 1;
    n->last_id = id;
    return id;
}

static void error_reply(const char *addr, uint64_t id, const char *msg, ks_ntf_reply_cb cb,
                        void *data)
{
    if (cb == NULL)
        return;
    Protocol__NotificationReply r = PROTOCOL__NOTIFICATION_REPLY__INIT;
    r.id = id;
    r.code = PROTOCOL__NOTIFICATION_REPLY_CODE__ERROR;
    r.data = (char *)(uintptr_t)msg;
    cb(addr, &r, data);
}

static int remember(struct ks_nodes *n, uint64_t id, int32_t type, ks_ntf_reply_cb cb,
                    void *data)
{
    if (n->nsent == n->capsent) {
        size_t ncap = n->capsent ? n->capsent * 2 : 16;
        struct ks_sent_ntf *ns = realloc(n->sent, ncap * sizeof(*ns));
        if (ns == NULL)
            return -1;
        n->sent = ns;
        n->capsent = ncap;
    }
    n->sent[n->nsent++] = (struct ks_sent_ntf){id, type, cb, data};
    return 0;
}

static int enqueue(struct ks_node *node, const uint8_t *buf, size_t len)
{
    if (node->stream != NULL)
        return ks_grpc_call_send(node->stream, buf, len);
    if (node->nqueue == node->capqueue) {
        size_t ncap = node->capqueue ? node->capqueue * 2 : 8;
        struct ks_queued_ntf *nq = realloc(node->queue, ncap * sizeof(*nq));
        if (nq == NULL)
            return -1;
        node->queue = nq;
        node->capqueue = ncap;
    }
    uint8_t *copy = malloc(len ? len : 1);
    if (copy == NULL)
        return -1;
    memcpy(copy, buf, len);
    node->queue[node->nqueue++] = (struct ks_queued_ntf){copy, len};
    return 0;
}

void ks_nodes_flush(struct ks_node *node)
{
    if (node->stream == NULL)
        return;
    for (size_t i = 0; i < node->nqueue; i++) {
        ks_grpc_call_send(node->stream, node->queue[i].buf, node->queue[i].len);
        free(node->queue[i].buf);
    }
    node->nqueue = 0;
}

uint64_t ks_nodes_send(struct ks_nodes *n, const char *addr, Protocol__Notification *ntf,
                       ks_ntf_reply_cb cb, void *data)
{
    ntf->id = ks_nodes_new_id(n);
    struct ks_node *node = ks_nodes_get(n, addr);
    if (node == NULL) {
        char msg[KS_NODE_ADDR_MAX + 32];
        snprintf(msg, sizeof(msg), "node not connected: %s", addr);
        error_reply(addr, ntf->id, msg, cb, data);
        return ntf->id;
    }
    size_t len;
    uint8_t *buf = ks_pb_pack(&ntf->base, &len);
    if (buf == NULL || remember(n, ntf->id, ntf->type, cb, data) < 0 ||
        enqueue(node, buf, len) < 0) {
        char msg[KS_NODE_ADDR_MAX + 64];
        snprintf(msg, sizeof(msg), "Notification not sent (%s)", addr);
        error_reply(addr, ntf->id, msg, cb, data);
    }
    free(buf);
    return ntf->id;
}

uint64_t ks_nodes_send_all(struct ks_nodes *n, Protocol__Notification *ntf, ks_ntf_reply_cb cb,
                           void *data)
{
    ntf->id = ks_nodes_new_id(n);
    size_t len;
    uint8_t *buf = ks_pb_pack(&ntf->base, &len);
    if (buf == NULL)
        return ntf->id;
    for (size_t i = 0; i < n->len; i++)
        enqueue(n->items[i], buf, len);
    remember(n, ntf->id, ntf->type, cb, data);
    free(buf);
    return ntf->id;
}

void ks_nodes_reply(struct ks_nodes *n, const char *addr, const Protocol__NotificationReply *r)
{
    for (size_t i = 0; i < n->nsent; i++) {
        struct ks_sent_ntf *s = &n->sent[i];
        if (s->id != r->id)
            continue;
        struct ks_sent_ntf copy = *s;
        /* only one-shot notifications are forgotten: TASK_START replies
         * keep coming with the same id */
        if (copy.type != PROTOCOL__ACTION__TASK_START) {
            memmove(s, s + 1, (n->nsent - i - 1) * sizeof(*s));
            n->nsent--;
        }
        if (copy.cb != NULL)
            copy.cb(addr, r, copy.data);
        return;
    }
    ks_debug("[Nodes]: reply notification not in the list: %llu", (unsigned long long)r->id);
}

uint64_t ks_nodes_reload_fw(struct ks_nodes *n, const char *addr, ks_ntf_reply_cb cb,
                            void *data)
{
    struct ks_node *node = ks_nodes_get(n, addr);
    if (node == NULL || node->fw == NULL)
        return 0;
    struct ks_arena a = {0};
    Protocol__Notification ntf = PROTOCOL__NOTIFICATION__INIT;
    ntf.type = PROTOCOL__ACTION__RELOAD_FW_RULES;
    ntf.sysfirewall = ks_sysfw_to_pb(&a, node->fw);
    uint64_t id = 0;
    if (ntf.sysfirewall != NULL)
        id = ks_nodes_send(n, addr, &ntf, cb, data);
    ks_arena_free(&a);
    return id;
}
