/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/stats.h"

#include <stdlib.h>

#include "common/log.h"
#include "daemon/config.h"
#include "daemon/procmon/process.h"
#include "daemon/protocol.h"
#include "daemon/rules/rule.h"
#include "tests/harness.h"

static struct ks_rule *mkrule(const char *name, const char *action)
{
    struct ks_operator op;
    memset(&op, 0, sizeof(op));
    op.type = "simple";
    op.operand = "true";
    op.data = "";
    return ks_rule_create(name, "", true, false, false, action, "always", &op);
}

static void mkconn(struct ks_conn *c, const char *dst, unsigned port, const char *host,
                   long long uid)
{
    memset(c, 0, sizeof(*c));
    c->protocol = "tcp";
    ks_ip_parse("10.0.0.2", &c->src_ip);
    ks_ip_parse(dst, &c->dst_ip);
    c->src_port = 40000;
    c->dst_port = port;
    c->dst_host = host;
    c->uid = uid;
}

TEST(counters)
{
    struct ks_stats s;
    ks_stats_init(&s, NULL);
    struct ks_proc *p = ks_proc_new_empty(10, "x");
    CHECK(p != NULL);
    struct ks_rule *allow = mkrule("a", "allow"), *deny = mkrule("d", "deny");
    struct ks_conn c;
    mkconn(&c, "1.1.1.1", 443, "one.one", 1000);

    ks_stats_on_connection(&s, &c, p, NULL, true);   /* missed */
    ks_stats_on_connection(&s, &c, p, allow, false); /* allowed */
    ks_stats_on_connection(&s, &c, p, deny, false);  /* denied */
    ks_stats_on_dns_response(&s);
    ks_stats_on_ignored(&s);

    CHECK_INT_EQ(s.connections, 3);
    CHECK_INT_EQ(s.rule_misses, 1);
    CHECK_INT_EQ(s.rule_hits, 2);
    CHECK_INT_EQ(s.accepted, 3); /* allow + dns + ignored; a miss counts as dropped */
    CHECK_INT_EQ(s.dropped, 2);
    CHECK_INT_EQ(s.dns_responses, 1);
    CHECK_INT_EQ(s.ignored, 1);
    CHECK_INT_EQ(s.nevents, 2); /* misses are not events */
    CHECK_INT_EQ(ks_stats_map_get(&s.by_address, "1.1.1.1"), 3);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_port, "443"), 3);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_uid, "1000"), 3);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_host, "one.one"), 3);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_proto, "tcp"), 3);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_executable, ""), 3);

    /* no host, unknown uid */
    mkconn(&c, "2.2.2.2", 80, "", -1);
    ks_stats_on_connection(&s, &c, p, allow, false);
    CHECK_INT_EQ(s.by_host.count, 1);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_uid, "-1"), 1);

    ks_rule_free(allow);
    ks_rule_free(deny);
    ks_proc_unref(p);
    ks_stats_free(&s);
}

TEST(maps_evict_the_least_hit)
{
    struct ks_stats s;
    ks_stats_init(&s, NULL);
    struct ks_stats_config cfg = {.max_stats = 2, .max_events = 0};
    ks_log_set_level(KS_LOG_WARNING);
    ks_stats_set_limits(&s, &cfg);
    ks_log_set_level(KS_LOG_INFO);
    CHECK_INT_EQ(s.max_stats, 2);
    CHECK_INT_EQ(s.max_events, 150); /* 0 keeps the default */
    struct ks_conn c;
    mkconn(&c, "1.1.1.1", 1, "", 0);
    ks_stats_on_connection(&s, &c, NULL, NULL, true);
    ks_stats_on_connection(&s, &c, NULL, NULL, true);
    mkconn(&c, "2.2.2.2", 2, "", 0);
    ks_stats_on_connection(&s, &c, NULL, NULL, true);
    mkconn(&c, "3.3.3.3", 3, "", 0);
    ks_stats_on_connection(&s, &c, NULL, NULL, true);
    CHECK_INT_EQ(s.by_address.count, 2);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_address, "1.1.1.1"), 2);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_address, "2.2.2.2"), 0);
    CHECK_INT_EQ(ks_stats_map_get(&s.by_address, "3.3.3.3"), 1);
    ks_stats_free(&s);
}

TEST(events_are_capped_and_shifted)
{
    struct ks_stats s;
    ks_stats_init(&s, NULL);
    s.max_events = 3;
    struct ks_rule *allow = mkrule("a", "allow");
    struct ks_conn c;
    for (unsigned i = 1; i <= 5; i++) {
        mkconn(&c, "1.1.1.1", i, "", 0);
        ks_stats_on_connection(&s, &c, NULL, allow, false);
    }
    CHECK_INT_EQ(s.nevents, 3);
    CHECK_INT_EQ(s.events[0]->conn.dst_port, 3);
    CHECK_INT_EQ(s.events[2]->conn.dst_port, 5);
    /* a miss still shifts the full backlog (upstream does), without adding */
    ks_stats_on_connection(&s, &c, NULL, NULL, true);
    CHECK_INT_EQ(s.nevents, 2);
    CHECK_INT_EQ(s.events[0]->conn.dst_port, 4);
    ks_rule_free(allow);
    ks_stats_free(&s);
}

TEST(serialize_and_empty)
{
    struct ks_stats s;
    ks_stats_init(&s, NULL);
    struct ks_arena a = {0};
    CHECK(ks_stats_serialize(&s, &a) == NULL); /* nothing new: no ping */

    struct ks_proc *p = ks_proc_new_empty(77, "curl");
    CHECK(p != NULL);
    free(p->path);
    p->path = strdup("/usr/bin/curl");
    ks_proc_sync(p);
    struct ks_rule *allow = mkrule("allow-curl", "allow");
    struct ks_conn c;
    mkconn(&c, "93.184.216.34", 443, "example.com", 1000);
    c.process = &p->view;
    ks_stats_on_connection(&s, &c, p, allow, false);
    ks_rule_free(allow); /* the event keeps its own copy */
    ks_proc_unref(p);    /* and its own reference */
    ks_stats_on_dns_response(&s);

    Protocol__Statistics *ps = ks_stats_serialize(&s, &a);
    CHECK(ps != NULL);
    size_t len;
    uint8_t *buf = ks_pb_pack(&ps->base, &len);
    ks_arena_free(&a);
    ks_stats_empty(&s);
    CHECK(buf != NULL);
    CHECK(!s.new_events);
    CHECK_INT_EQ(s.nevents, 0);
    CHECK(ks_stats_serialize(&s, &a) == NULL);

    Protocol__Statistics *w = (Protocol__Statistics *)ks_pb_unpack(
        &protocol__statistics__descriptor, buf, len);
    free(buf);
    CHECK(w != NULL);
    CHECK_STR_EQ(w->daemon_version, KS_UPSTREAM_VERSION);
    CHECK_INT_EQ(w->connections, 1);
    CHECK_INT_EQ(w->accepted, 2);
    CHECK_INT_EQ(w->dns_responses, 1);
    CHECK_INT_EQ(w->n_events, 1);
    CHECK_STR_EQ(w->events[0]->rule->name, "allow-curl");
    CHECK_STR_EQ(w->events[0]->connection->process_path, "/usr/bin/curl");
    CHECK_STR_EQ(w->events[0]->connection->dst_host, "example.com");
    CHECK_INT_EQ(strlen(w->events[0]->time), 19); /* "2006-01-02 15:04:05" */
    CHECK(w->events[0]->unixnano > 0);
    CHECK_INT_EQ(w->n_by_host, 1);
    CHECK_STR_EQ(w->by_host[0]->key, "example.com");
    CHECK_INT_EQ(w->by_host[0]->value, 1);
    CHECK_INT_EQ(w->n_by_executable, 1);
    CHECK_STR_EQ(w->by_executable[0]->key, "/usr/bin/curl");
    protobuf_c_message_free_unpacked(&w->base, NULL);

    /* the maps survive emptyStats() */
    CHECK_INT_EQ(ks_stats_map_get(&s.by_port, "443"), 1);
    ks_stats_free(&s);
}

int main(void)
{
    RUN(counters);
    RUN(maps_evict_the_least_hit);
    RUN(events_are_capped_and_shifted);
    RUN(serialize_and_empty);
    return harness_report();
}
