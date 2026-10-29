/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The daemons (nodes) connected to the UI. Port of upstream
 * ui/opensnitch/nodes.py: each node is known by "proto:addr" from its
 * gRPC peer ("unix:/local", "ipv4:192.168.1.2"), keeps the ClientConfig it
 * subscribed with, and has a queue of notifications that go out on its
 * Notifications stream.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_nodes owns every node, their configs (unpacked
 * messages and firewall), queued notifications (packed) and the records of sent
 * notifications. A node's `stream` is borrowed from the gRPC connection
 * (cleared by the owner when the call closes).
 */
#ifndef KS_UI_NODES_H
#define KS_UI_NODES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "common/grpc/grpc.h"
#include "common/pb/ui.pb-c.h"

struct ks_sysfw;

#define KS_NODE_ADDR_MAX 160

struct ks_queued_ntf {
    uint8_t *buf;
    size_t len;
};

struct ks_node {
    char addr[KS_NODE_ADDR_MAX]; /* "proto:addr" */
    Protocol__ClientConfig *config;
    struct ks_sysfw *fw; /* node['firewall']: the editable system firewall, or NULL */
    bool online;
    time_t last_seen;
    struct ks_grpc_call *stream; /* the open Notifications call, if any */
    struct ks_queued_ntf *queue;
    size_t nqueue, capqueue;
};

/* Called with the daemon's reply to a notification we sent. */
typedef void (*ks_ntf_reply_cb)(const char *addr, const Protocol__NotificationReply *reply,
                                void *data);

struct ks_sent_ntf {
    uint64_t id;
    int32_t type;
    ks_ntf_reply_cb cb;
    void *data;
};

struct ks_nodes {
    struct ks_node **items;
    size_t len, cap;
    struct ks_sent_ntf *sent;
    size_t nsent, capsent;
    uint64_t last_id;
};

void ks_nodes_init(struct ks_nodes *n);
void ks_nodes_free(struct ks_nodes *n);

/* Nodes.get_addr(): "unix:" -> ("unix", "/local"), "ipv4:1.2.3.4:5" ->
 * ("ipv4", "1.2.3.4"), and so on (split on ":"; an IPv6 peer
 * "ipv6:[::1]:5" gives "[", as upstream). Writes "proto:addr". */
void ks_nodes_peer_addr(const char *peer, char *out, size_t len);
/* NetworkInterfaces.list(): name and IPv4 address of the interfaces. */
struct ks_iface {
    char name[16];
    char ip[16];
};
size_t ks_net_ifaces(struct ks_iface *out, size_t max);
/* Nodes.is_local(addr): "unix..." or an ipv4/ipv6 address of this host
 * (the IPv4 of an interface, as NetworkInterfaces.list() finds them). */
bool ks_nodes_is_local(const char *addr);
/* The proto part of a peer, for _is_local_request(). */
bool ks_nodes_peer_is_unix(const char *peer);

/* Nodes.add(): adds or refreshes the node of `peer` with `config`
 * (owned from now on; may be NULL). Returns the node. */
struct ks_node *ks_nodes_add(struct ks_nodes *n, const char *peer,
                             Protocol__ClientConfig *config);
struct ks_node *ks_nodes_get(const struct ks_nodes *n, const char *addr);
/* Nodes.delete() by peer. The stream, if open, is not touched. */
void ks_nodes_delete(struct ks_nodes *n, const char *peer);
size_t ks_nodes_count(const struct ks_nodes *n);
/* The node's hostname (ClientConfig.name), "" if unknown. */
const char *ks_nodes_hostname(const struct ks_nodes *n, const char *addr);

/* A new notification id: int(str(time.time()).replace(".", "")), made
 * unique. */
uint64_t ks_nodes_new_id(struct ks_nodes *n);

/* Nodes.send_notification(): sets ntf->id, packs it, and sends it on the
 * node's stream or queues it until the stream opens. If the node isn't
 * connected, `cb` gets an ERROR reply right away. Returns the id. */
uint64_t ks_nodes_send(struct ks_nodes *n, const char *addr, Protocol__Notification *ntf,
                       ks_ntf_reply_cb cb, void *data);
/* Nodes.send_notifications(): to every node. */
uint64_t ks_nodes_send_all(struct ks_nodes *n, Protocol__Notification *ntf, ks_ntf_reply_cb cb,
                           void *data);
/* Sends what's queued for the node on its (now open) stream. */
void ks_nodes_flush(struct ks_node *node);

/* Nodes.reload_fw(): a RELOAD_FW_RULES notification with the node's
 * firewall (node->fw). Returns the id, 0 if the node has no firewall. */
uint64_t ks_nodes_reload_fw(struct ks_nodes *n, const char *addr, ks_ntf_reply_cb cb,
                            void *data);

/* Nodes.reply_notification(): routes a reply to its callback. */
void ks_nodes_reply(struct ks_nodes *n, const char *addr, const Protocol__NotificationReply *r);

#endif
