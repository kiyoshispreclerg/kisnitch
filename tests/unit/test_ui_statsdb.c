/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/statsdb.c: nodes, events, counters and alerts in the UI database, as
 * upstream service.py/nodes.py write them.
 */
#include "ui/statsdb.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tests/harness.h"

static struct ks_db *db;
static struct ks_rulesdb rules;
static struct ks_statsdb sdb;

static void setup(void)
{
    char err[128];
    setenv("TZ", "UTC", 1);
    tzset();
    db = ks_db_open(NULL, false, err, sizeof(err));
    ks_rulesdb_init(&rules);
    ks_rulesdb_attach(&rules, db);
    ks_statsdb_init(&sdb, db, &rules);
}

static void teardown(void)
{
    ks_statsdb_free(&sdb);
    ks_rulesdb_free(&rules);
    ks_db_close(db);
}

static char *text(const char *sql)
{
    static char buf[256];
    sqlite3_stmt *st;
    buf[0] = '\0';
    if (sqlite3_prepare_v2(ks_db_handle(db), sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *v = (const char *)sqlite3_column_text(st, 0);
            snprintf(buf, sizeof(buf), "%s", v ? v : "<null>");
        }
        sqlite3_finalize(st);
    }
    return buf;
}

TEST(formats)
{
    char b[64];
    setenv("TZ", "UTC", 1);
    tzset();
    ks_statsdb_timedelta(59, b, sizeof(b));
    CHECK_STR_EQ(b, "0:00:59");
    ks_statsdb_timedelta(3 * 3600 + 25 * 60 + 7, b, sizeof(b));
    CHECK_STR_EQ(b, "3:25:07");
    ks_statsdb_timedelta(86400 + 5, b, sizeof(b));
    CHECK_STR_EQ(b, "1 day, 0:00:05");
    ks_statsdb_timedelta(3 * 86400 + 3661, b, sizeof(b));
    CHECK_STR_EQ(b, "3 days, 1:01:01");
    /* whole seconds carry no fraction, as str(datetime) */
    ks_statsdb_event_time(1700000000LL * 1000000000LL, b, sizeof(b));
    CHECK_STR_EQ(b, "2023-11-14 22:13:20");
    ks_statsdb_event_time(1700000000LL * 1000000000LL + 123456000LL, b, sizeof(b));
    CHECK_STR_EQ(b, "2023-11-14 22:13:20.123456");
    ks_statsdb_user_id("0", b, sizeof(b));
    CHECK_STR_EQ(b, "root (0)");
    ks_statsdb_user_id("4294967000", b, sizeof(b));
    CHECK_STR_EQ(b, "4294967000");
    ks_statsdb_user_id("abc", b, sizeof(b));
    CHECK_STR_EQ(b, "abc");
}

TEST(nodes_table)
{
    setup();
    ks_statsdb_node_insert(&sdb, "unix:/local", "host1", "1.8.0", KS_NODE_ONLINE);
    CHECK_INT_EQ(ks_db_count(db, "nodes"), 1);
    CHECK_STR_EQ(text("SELECT status FROM nodes"), KS_NODE_ONLINE);
    CHECK_STR_EQ(text("SELECT hostname||'/'||version||'/'||cons FROM nodes"), "host1/1.8.0/0");
    ks_statsdb_node_update(&sdb, "unix:/local", "host2", "1.8.1", KS_NODE_OFFLINE);
    CHECK_STR_EQ(text("SELECT hostname||'/'||version||'/'||status FROM nodes"),
                 "host2/1.8.1/" KS_NODE_OFFLINE);
    ks_statsdb_node_insert(&sdb, "unix:/local", "host1", "1.8.0", KS_NODE_ONLINE); /* REPLACE */
    CHECK_INT_EQ(ks_db_count(db, "nodes"), 1);
    ks_statsdb_reset_status(&sdb);
    CHECK_STR_EQ(text("SELECT status FROM nodes"), KS_NODE_OFFLINE);
    teardown();
}

static Protocol__Statistics *make_stats(Protocol__Event *evs, size_t n, Protocol__Event **ptrs)
{
    static Protocol__Statistics st;
    protocol__statistics__init(&st);
    for (size_t i = 0; i < n; i++)
        ptrs[i] = &evs[i];
    st.events = ptrs;
    st.n_events = n;
    st.daemon_version = "1.8.0";
    st.uptime = 3725;
    st.rules = 4;
    st.connections = 99;
    st.dropped = 3;
    return &st;
}

TEST(populate_events_and_counters)
{
    setup();
    ks_statsdb_node_insert(&sdb, "unix:/local", "h", "1.8.0", KS_NODE_ONLINE);
    const char *v[KS_RF_COUNT] = {"old", "unix:/local", "r1", "True", "False", "allow",
                                  "always", "simple", "False", "process.path", "/bin/x", "",
                                  "False", ""};
    ks_rulesdb_add_row(&rules, v);

    Protocol__Connection cn;
    protocol__connection__init(&cn);
    cn.protocol = "tcp";
    cn.src_ip = "10.0.0.2";
    cn.src_port = 40000;
    cn.dst_ip = "93.184.216.34";
    cn.dst_host = "example.com";
    cn.dst_port = 443;
    cn.user_id = 0;
    cn.process_id = 1234;
    cn.process_path = "/usr/bin/curl";
    cn.process_cwd = "/root";
    char *argv[] = {"curl", "-s", "https://example.com"};
    cn.process_args = argv;
    cn.n_process_args = 3;
    Protocol__Rule rl;
    protocol__rule__init(&rl);
    rl.name = "r1";
    rl.action = "allow";
    Protocol__Event ev[2];
    protocol__event__init(&ev[0]);
    protocol__event__init(&ev[1]);
    ev[0].connection = &cn;
    ev[0].rule = &rl;
    ev[0].unixnano = 1700000000LL * 1000000000LL;
    /* UNIQUE(node, action, ..., src_port, ...) leaves out the time: the same
     * connection twice is one row (INSERT OR IGNORE), so this one differs */
    Protocol__Connection cn2 = cn;
    cn2.src_port = 40001;
    ev[1] = ev[0];
    ev[1].connection = &cn2;
    ev[1].unixnano += 1000000000LL;
    Protocol__Event *ptrs[2];
    Protocol__Statistics *st = make_stats(ev, 2, ptrs);

    Protocol__Statistics__ByHostEntry he = PROTOCOL__STATISTICS__BY_HOST_ENTRY__INIT;
    he.key = "example.com";
    he.value = 5;
    Protocol__Statistics__ByHostEntry *hp[1] = {&he};
    st->by_host = hp;
    st->n_by_host = 1;
    Protocol__Statistics__ByUidEntry ue = PROTOCOL__STATISTICS__BY_UID_ENTRY__INIT;
    ue.key = "0";
    ue.value = 7;
    Protocol__Statistics__ByUidEntry *up[1] = {&ue};
    st->by_uid = up;
    st->n_by_uid = 1;

    struct ks_stats_refresh r = ks_statsdb_populate(&sdb, "unix:/local", "h", "1.8.0", st);
    CHECK(r.main);
    CHECK(r.details);
    CHECK_STR_EQ(text("SELECT daemon_version||'/'||daemon_uptime||'/'||daemon_rules||'/'||cons||"
                      "'/'||cons_dropped||'/'||status FROM nodes"),
                 "1.8.0/1:02:05/4/99/3/" KS_NODE_ONLINE);
    CHECK_INT_EQ(ks_db_count(db, "connections"), 2);
    CHECK_STR_EQ(text("SELECT time||'|'||node||'|'||action||'|'||protocol||'|'||src_port||'|'||"
                      "dst_host||'|'||uid||'|'||pid||'|'||process||'|'||process_args||'|'||"
                      "process_cwd||'|'||rule FROM connections ORDER BY time LIMIT 1"),
                 "2023-11-14 22:13:20|unix:/local|allow|tcp|40000|example.com|0|1234|"
                 "/usr/bin/curl|curl -s https://example.com|/root|r1");
    CHECK_STR_EQ(text("SELECT time FROM rules WHERE name='r1'"), "2023-11-14 22:13:21");
    CHECK_STR_EQ(rules.rows[0].f[KS_RF_TIME], "2023-11-14 22:13:21");
    CHECK_STR_EQ(text("SELECT hits FROM hosts WHERE what='example.com'"), "5");
    CHECK_STR_EQ(text("SELECT hits FROM users WHERE what='root (0)'"), "7");

    /* the same Ping again: nothing is new */
    r = ks_statsdb_populate(&sdb, "unix:/local", "h", "1.8.0", st);
    CHECK(!r.main);
    CHECK(!r.details);

    /* a counter that moved is written again (REPLACE, not added) */
    he.value = 9;
    ev[0].unixnano += 5000000000LL;
    r = ks_statsdb_populate(&sdb, "unix:/local", "h", "1.8.0", st);
    CHECK(r.main); /* ev[0] has a new id */
    CHECK(r.details);
    CHECK_STR_EQ(text("SELECT hits FROM hosts WHERE what='example.com'"), "9");
    CHECK_INT_EQ(ks_db_count(db, "hosts"), 1);

    /* a node that left starts from scratch */
    ks_statsdb_node_forget(&sdb, "unix:/local");
    r = ks_statsdb_populate(&sdb, "unix:/local", "h", "1.8.0", st);
    CHECK(r.main);
    CHECK(r.details);
    teardown();
}

TEST(alerts_table)
{
    setup();
    ks_statsdb_alert(&sdb, "unix:/local", "WARNING", "KERNEL EVENT", "text\n/bin/x");
    CHECK_INT_EQ(ks_db_count(db, "alerts"), 1);
    CHECK_STR_EQ(text("SELECT node||'|'||type||'|'||what||'|'||body||'|'||status FROM alerts"),
                 "unix:/local|WARNING|KERNEL EVENT|text\n/bin/x|0");
    /* time has microseconds, "%Y-%m-%d %H:%M:%S.%f" */
    CHECK_INT_EQ((int)strlen(text("SELECT time FROM alerts")), 26);
    teardown();
}

int main(void)
{
    RUN(formats);
    RUN(nodes_table);
    RUN(populate_events_and_counters);
    RUN(alerts_table);
    return harness_report();
}
