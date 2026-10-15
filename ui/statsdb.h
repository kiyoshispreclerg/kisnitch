/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * What the UI keeps in its database about the nodes and what they report:
 * the nodes table (ui/opensnitch/nodes.py insert/update/update_all/
 * reset_status), the statistics of every Ping (service.py
 * _populate_stats, _populate_stats_details, _populate_stats_events) and
 * the alerts table (service.py _on_new_alert).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_statsdb borrows the database and the rules (they must
 * outlive it) and owns, per node, the events and counters of the last
 * Ping (_last_stats and _last_items).
 */
#ifndef KS_UI_STATSDB_H
#define KS_UI_STATSDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/pb/ui.pb-c.h"
#include "ui/db.h"
#include "ui/nodes.h"
#include "ui/rulesdb.h"

/* Nodes.ONLINE / Nodes.OFFLINE: "✓ online" and "☓ offline" */
#define KS_NODE_ONLINE  "\xe2\x9c\x93 online"
#define KS_NODE_OFFLINE "\xe2\x98\x93 offline"

struct ks_stats_node_cache;

struct ks_statsdb {
    struct ks_db *db;
    struct ks_rulesdb *rules;
    struct ks_stats_node_cache *caches;
};

void ks_statsdb_init(struct ks_statsdb *s, struct ks_db *db, struct ks_rulesdb *rules);
void ks_statsdb_free(struct ks_statsdb *s);

/* Nodes.reset_status(): every node offline (done when the UI starts). */
void ks_statsdb_reset_status(struct ks_statsdb *s);
/* Nodes.insert(): a node that subscribed. `name` and `version` come from
 * its ClientConfig. */
void ks_statsdb_node_insert(struct ks_statsdb *s, const char *addr, const char *name,
                            const char *version, const char *status);
/* Nodes.update(): hostname, version, last_connection and status. */
void ks_statsdb_node_update(struct ks_statsdb *s, const char *addr, const char *name,
                            const char *version, const char *status);
/* service._delete_node(): forgets what was last seen from the node. */
void ks_statsdb_node_forget(struct ks_statsdb *s, const char *addr);

/* _populate_stats(): the node row, the new events (connections table and
 * the time of the rules that matched), and the by_* counters that changed.
 * `name` and `version` are the node's. Returns the two refresh flags. */
struct ks_stats_refresh {
    bool main, details;
};
struct ks_stats_refresh ks_statsdb_populate(struct ks_statsdb *s, const char *addr,
                                            const char *name, const char *version,
                                            const Protocol__Statistics *st);

/* _on_new_alert(): a row in the alerts table. `type` is "INFO", "WARNING"
 * or "ERROR"; `what` is "GENERIC" or "KERNEL EVENT". */
void ks_statsdb_alert(struct ks_statsdb *s, const char *node, const char *type,
                      const char *what, const char *body);

/* str(datetime.fromtimestamp(unixnano / 1000000000)) */
void ks_statsdb_event_time(int64_t unixnano, char *buf, size_t len);
/* str(timedelta(seconds=n)) */
void ks_statsdb_timedelta(uint64_t secs, char *buf, size_t len);
/* Utils.get_user_id(): "name (uid)" if the uid has a passwd entry, else
 * the uid text. */
void ks_statsdb_user_id(const char *uid, char *buf, size_t len);

#endif
