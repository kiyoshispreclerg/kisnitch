/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/statsq.c: the queries of the statistics window run on a real
 * database, with the column names the upstream window shows.
 */
#include "ui/statsq.h"

#include <stdlib.h>
#include <string.h>

#include "ui/db.h"
#include "tests/harness.h"

static struct ks_db *db;

static void conn(const char *time, const char *node, const char *action, const char *sport,
                 const char *dip, const char *dhost, const char *dport, const char *uid,
                 const char *pid, const char *proc, const char *rule)
{
    const char *a[15] = {time, node, action, "tcp", "10.0.0.2", sport, dip, dhost, dport, uid,
                         pid, proc, "arg", "/", rule};
    ks_db_run(db,
              "INSERT INTO connections (time,node,action,protocol,src_ip,src_port,dst_ip,"
              "dst_host,dst_port,uid,pid,process,process_args,process_cwd,rule) "
              "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              a, 15, NULL);
}

static void setup(void)
{
    char err[128];
    db = ks_db_open(NULL, false, err, sizeof(err));
    conn("2026-01-01 10:00:00", "unix:/local", "allow", "1", "1.1.1.1", "one.example", "443",
         "0", "10", "/usr/bin/curl", "r-curl");
    conn("2026-01-01 10:00:01", "unix:/local", "deny", "2", "2.2.2.2", "two.example", "80",
         "1000", "11", "/usr/bin/wget", "r-wget");
    conn("2026-01-01 10:00:02", "ipv4:10.1.1.1", "allow", "3", "1.1.1.1", "one.example", "443",
         "1000", "12", "/usr/bin/curl", "r-curl");
    conn("2026-01-01 10:00:03", "unix:/local", "allow", "4", "1.1.1.1", "one.example", "80",
         "0", "10", "/usr/bin/curl", "r-curl");
    ks_db_exec(db, "INSERT INTO hosts VALUES ('one.example', 3), ('two.example', 1)");
    ks_db_exec(db, "INSERT INTO procs VALUES ('/usr/bin/curl', 3), ('/usr/bin/wget', 1)");
    ks_db_exec(db, "INSERT INTO users VALUES ('root (0)', 2), ('1000', 2)");
    ks_db_exec(db, "INSERT INTO nodes (addr,status,hostname,version,last_connection) VALUES "
                   "('unix:/local','on','h1','1.8.0','t'),('ipv4:10.1.1.1','on','h2','1.8.0','t')");
    const char *a[14] = {"t", "unix:/local", "r-curl", "True", "False", "allow", "always",
                         "simple", "False", "process.path", "/usr/bin/curl", "d", "False", "c"};
    ks_db_run(db,
              "INSERT INTO rules (time,node,name,enabled,precedence,action,duration,"
              "operator_type,operator_sensitive,operator_operand,operator_data,description,"
              "nolog,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              a, 14, NULL);
    a[2] = "r-tmp";
    a[6] = "5m";
    ks_db_run(db,
              "INSERT INTO rules (time,node,name,enabled,precedence,action,duration,"
              "operator_type,operator_sensitive,operator_operand,operator_data,description,"
              "nolog,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              a, 14, NULL);
}

/* rows of a query, -1 if it fails; the first column's name in `col0` */
static int run(char *sql, char *col0, size_t len)
{
    if (sql == NULL)
        return -1;
    sqlite3_stmt *st;
    int n = -1;
    if (sqlite3_prepare_v2(ks_db_handle(db), sql, -1, &st, NULL) == SQLITE_OK) {
        n = 0;
        if (col0 != NULL)
            snprintf(col0, len, "%s", sqlite3_column_name(st, 0));
        while (sqlite3_step(st) == SQLITE_ROW)
            n++;
        sqlite3_finalize(st);
    } else {
        fprintf(stderr, "bad SQL: %s\n  %s\n", sql, sqlite3_errmsg(ks_db_handle(db)));
    }
    free(sql);
    return n;
}

TEST(events)
{
    setup();
    char c[64];
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "", 0, "1", 1, 4), c, sizeof(c)), 4);
    CHECK_STR_EQ(c, "Time");
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "", 0, "1", 1, 0), NULL, 0), 4);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "", 2, "1", 1, 4), NULL, 0), 1);   /* deny */
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "", 1, "1", 1, 4), NULL, 0), 3);   /* allow */
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "wget", 0, "1", 1, 4), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "curl", 1, "1", 1, 4), NULL, 0), 3);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "curl", 2, "1", 1, 4), NULL, 0), 0);
    /* a quote is data, not SQL */
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "x' OR '1'='1", 0, "1", 1, 4), NULL, 0), 0);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_MAIN, "it's", 0, "1", 1, 4), NULL, 0), 0);
    char *q = ks_sq_list(KS_TAB_MAIN, "", 0, "1", 0, 1);
    CHECK_STR_HAS(q, "ORDER BY 1 ASC LIMIT 100");
    free(q);
    ks_db_close(db);
}

TEST(lists)
{
    setup();
    char c[64];
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_NODES, "", 0, "3,2,1", 1, 4), c, sizeof(c)), 2);
    CHECK_STR_EQ(c, "LastConnection");
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_NODES, "h2", 0, "3,2,1", 1, 4), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_RULES, "", 0, "2", 0, 4), c, sizeof(c)), 2);
    CHECK_STR_EQ(c, "Time");
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_RULES, "tmp", 0, "2", 0, 4), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_RULES, "/usr/bin", 0, "2", 0, 4), NULL, 0), 2);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_HOSTS, "", 0, "2", 1, 0), c, sizeof(c)), 2);
    CHECK_STR_EQ(c, "what");
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_HOSTS, "two", 0, "2", 1, 0), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_PROCS, "", 0, "2", 1, 0), NULL, 0), 2);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_USERS, "root", 0, "2", 1, 0), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_ADDRS, "", 0, "2", 1, 0), NULL, 0), 0);
    CHECK_INT_EQ(run(ks_sq_list(KS_TAB_PORTS, "", 0, "2", 1, 0), NULL, 0), 0);

    CHECK_INT_EQ(run(ks_sq_rules(KS_RULES_ALL, NULL, "", "2", 0, 4), NULL, 0), 2);
    CHECK_INT_EQ(run(ks_sq_rules(KS_RULES_PERMANENT, NULL, "", "2", 0, 4), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_rules(KS_RULES_TEMPORARY, NULL, "", "2", 0, 4), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_rules(KS_RULES_NODE, "unix:/local", "curl", "2", 0, 4), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_rules(KS_RULES_NODE, "ipv4:10.1.1.1", "", "2", 0, 4), NULL, 0), 0);
    CHECK_INT_EQ(run(ks_sq_rules(KS_RULES_PERMANENT, NULL, "tmp", "2", 0, 4), NULL, 0), 0);
    CHECK_INT_EQ(run(ks_sq_alerts("1", 0, 4), c, sizeof(c)), 0);
    CHECK_STR_EQ(c, "Time");
    ks_db_close(db);
}

TEST(details)
{
    setup();
    char c[64];
    /* the node: the grouping leaves 4 distinct connections on 2 nodes */
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_NODES, "unix:/local", NULL, "", "3,2,1", 1, 4), c,
                     sizeof(c)), 3);
    CHECK_STR_EQ(c, "Time");
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_NODES, "unix:/local", NULL, "wget", "3,2,1", 1, 4),
                     NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_HOSTS, "one.example", NULL, "", "1", 1, 4), NULL, 0), 3);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_HOSTS, "one.example", NULL, "80", "1", 1, 4), NULL,
                     0), 1);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_PROCS, "/usr/bin/curl", NULL, "", "1", 1, 4), NULL, 0),
                 3);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_ADDRS, "1.1.1.1", NULL, "", "1", 1, 4), NULL, 0), 3);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_PORTS, "80", NULL, "", "1", 1, 4), NULL, 0), 2);
    /* the field of the view is not filtered: "80" is the port itself */
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_PORTS, "80", NULL, "wget", "1", 1, 4), NULL, 0), 1);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_USERS, "root (0)", NULL, "", "1", 1, 4), NULL, 0), 2);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_USERS, "1000", NULL, "", "1", 1, 4), NULL, 0), 2);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_RULES, "r-curl", "unix:/local", "", "1", 1, 4), NULL, 0),
                 2);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_RULES, "r-curl", "ipv4:10.1.1.1", "", "1", 1, 4), NULL,
                     0), 1);
    CHECK_INT_EQ(run(ks_sq_detail(KS_TAB_HOSTS, "o'ne", NULL, "it's", "1", 1, 4), NULL, 0), 0);
    CHECK(ks_sq_detail(KS_TAB_MAIN, "x", NULL, "", "1", 1, 4) == NULL);
    ks_db_close(db);
}

TEST(escape)
{
    char *e = ks_sq_escape("a'b''c");
    CHECK_STR_EQ(e, "a''b''''c");
    free(e);
}

int main(void)
{
    RUN(events);
    RUN(lists);
    RUN(details);
    RUN(escape);
    return harness_report();
}
