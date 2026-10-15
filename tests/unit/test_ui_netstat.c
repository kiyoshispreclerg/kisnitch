/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/netstat.c: the sockets-monitor task's JSON (the shape of the Go
 * structs in daemon/tasks/socketsmonitor and daemon/netlink) in the
 * `sockets` table, and the names of the numbers.
 */
#include "ui/netstat.h"

#include <stdlib.h>
#include <string.h>

#include "ui/statsq.h"
#include "tests/harness.h"

static struct ks_db *db;

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

static const char *sample =
    "{\"Table\": ["
    "{\"Socket\": {\"ID\": {\"Source\": \"127.0.0.1\", \"Destination\": \"0.0.0.0\", "
    "\"Cookie\": [4294967295, 12], \"Interface\": 0, \"SourcePort\": 631, "
    "\"DestinationPort\": 0}, \"Expires\": 0, \"RQueue\": 0, \"WQueue\": 128, \"UID\": 0, "
    "\"INode\": 12345, \"Family\": 2, \"State\": 10, \"Timer\": 0, \"Retrans\": 0}, "
    "\"Iface\": \"\", \"PID\": 4242, \"Mark\": 0, \"Proto\": 6},"
    "{\"Socket\": {\"ID\": {\"Source\": null, \"Destination\": null, \"Cookie\": [1, 2], "
    "\"Interface\": 3, \"SourcePort\": 0, \"DestinationPort\": 0}, \"Expires\": 0, "
    "\"RQueue\": 0, \"WQueue\": 0, \"UID\": 1000, \"INode\": 999, \"Family\": 17, "
    "\"State\": 0, \"Timer\": 0, \"Retrans\": 0}, \"Iface\": \"eth0\", \"PID\": -1, "
    "\"Mark\": 0, \"Proto\": 3},"
    "null"
    "], \"Processes\": {\"4242\": {\"Path\": \"/usr/sbin/cupsd\", \"Comm\": \"cupsd\"}, "
    "\"-1\": {}}}";

TEST(names)
{
    CHECK_STR_EQ(ks_sockets_state("10"), "LISTEN");
    CHECK_STR_EQ(ks_sockets_state("0"), "LISTEN");
    CHECK_STR_EQ(ks_sockets_state("1"), "Established");
    CHECK_STR_EQ(ks_sockets_proto("6"), "TCP");
    CHECK_STR_EQ(ks_sockets_proto("34525"), "ETH_P_IPV6");
    CHECK_STR_EQ(ks_sockets_family("17"), "AF_PACKET");
    CHECK(ks_sockets_state("99") == NULL);
    CHECK_STR_EQ(ks_netstat_display(2, "10"), "LISTEN");
    CHECK_STR_EQ(ks_netstat_display(7, "17"), "UDP");
    CHECK_STR_EQ(ks_netstat_display(10, "2"), "AF_INET");
    CHECK_STR_EQ(ks_netstat_display(2, "77"), ""); /* KeyError: an empty cell */
    CHECK_STR_EQ(ks_netstat_display(3, "631"), "631");
}

TEST(update_table)
{
    char err[128] = "";
    db = ks_db_open(NULL, false, err, sizeof(err));
    ks_db_exec(db, "INSERT INTO sockets (node, src_port) VALUES ('old', '1')");
    CHECK_INT_EQ(ks_netstat_update(db, "unix:/local", sample, err, sizeof(err)), 2);
    CHECK_INT_EQ((int)ks_db_count(db, "sockets"), 2); /* the old rows are gone */
    CHECK_STR_EQ(text("SELECT node||'|'||src_port||'|'||src_ip||'|'||dst_ip||'|'||dst_port||'|'||proto||'|'||"
                      "uid||'|'||inode||'|'||iface||'|'||family||'|'||state||'|'||cookies||'|'||"
                      "rqueue||'|'||wqueue||'|'||expires||'|'||retrans||'|'||timer||'|'||proc_path||'|'||"
                      "proc_comm||'|'||proc_pid FROM sockets WHERE src_port='631'"),
                 "unix:/local|631|127.0.0.1|0.0.0.0|0|6|0|12345|0|2|10|[4294967295, 12]|0|128|0|0|0|"
                 "/usr/sbin/cupsd|cupsd|4242");
    /* a packet socket: no addresses, no process; the interface by name */
    CHECK_STR_EQ(text("SELECT iface||'|'||ifnull(src_ip,'NULL')||'|'||proc_path||'|'||proc_pid||'|'||family "
                      "FROM sockets WHERE inode='999'"),
                 "eth0|NULL||" "|17");
    /* what the tab shows: the netstat query, with the filter line */
    char *q = ks_sq_list(KS_TAB_NETSTAT, "cups", 0, "2", 1, 4);
    CHECK_STR_HAS(q, "proc_comm as Comm");
    CHECK_STR_HAS(q, "WHERE proc_comm LIKE '%cups%'");
    sqlite3_stmt *st;
    CHECK(sqlite3_prepare_v2(ks_db_handle(db), q, -1, &st, NULL) == SQLITE_OK);
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW)
        n++;
    sqlite3_finalize(st);
    free(q);
    CHECK_INT_EQ(n, 1);
    ks_db_close(db);
}

TEST(errors)
{
    char err[128] = "";
    db = ks_db_open(NULL, false, err, sizeof(err));
    CHECK_INT_EQ(ks_netstat_update(db, "n", "not json", err, sizeof(err)), -1);
    CHECK(err[0] != '\0');
    err[0] = '\0';
    CHECK_INT_EQ(ks_netstat_update(db, "n", "{\"Processes\": {}}", err, sizeof(err)), -1);
    CHECK_STR_HAS(err, "Table");
    err[0] = '\0';
    CHECK_INT_EQ(ks_netstat_update(db, "n", "{\"Table\": null, \"Processes\": {}}", err, sizeof(err)), -1);
    err[0] = '\0';
    /* a socket without its ID: the transaction is rolled back */
    CHECK_INT_EQ(ks_netstat_update(db, "n",
                                   "{\"Table\": [{\"Socket\": {}, \"Iface\": \"\", \"PID\": -1, \"Proto\": 6}], "
                                   "\"Processes\": {}}",
                                   err, sizeof(err)), -1);
    CHECK_STR_HAS(err, "ID");
    CHECK_INT_EQ((int)ks_db_count(db, "sockets"), 0);
    ks_db_close(db);
}

int main(void)
{
    RUN(names);
    RUN(update_table);
    RUN(errors);
    return harness_report();
}
