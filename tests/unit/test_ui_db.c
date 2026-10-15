/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/db.c: the upstream schema, migrations, purge by days, and the rules
 * table written through by ui/rulesdb.c.
 */
#include "ui/db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ui/rulesdb.h"
#include "tests/harness.h"

static char path[64];

static void tmp_path(void)
{
    snprintf(path, sizeof(path), "/tmp/ks-test-db-XXXXXX");
    int fd = mkstemp(path);
    if (fd >= 0)
        close(fd);
    unlink(path);
}

static int64_t scalar(struct ks_db *db, const char *sql)
{
    sqlite3_stmt *st;
    int64_t v = -1;
    if (sqlite3_prepare_v2(ks_db_handle(db), sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return v;
}

TEST(schema_is_upstreams)
{
    char err[128];
    struct ks_db *db = ks_db_open(NULL, false, err, sizeof(err));
    CHECK(db != NULL);
    CHECK_INT_EQ(ks_db_schema_version(db), KS_DB_VERSION);
    static const char *const tables[] = {"connections", "nodes", "rules", "alerts",
                                         "sockets", "hosts", "procs", "addrs", "ports", "users"};
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='%s'",
                 tables[i]);
        CHECK_INT_EQ(scalar(db, sql), 1);
    }
    /* 14 columns in rules, in RuleFields order */
    CHECK_INT_EQ(scalar(db, "SELECT count(*) FROM pragma_table_info('rules')"), 14);
    CHECK_INT_EQ(scalar(db, "SELECT cid FROM pragma_table_info('rules') WHERE name='created'"), 13);
    CHECK_INT_EQ(scalar(db, "SELECT count(*) FROM pragma_table_info('connections')"), 15);
    /* sck_dsthost_index is the one upstream cannot create (no such column) */
    CHECK_INT_EQ(scalar(db, "SELECT count(*) FROM sqlite_master WHERE name='sck_dsthost_index'"), 0);
    CHECK_INT_EQ(scalar(db, "SELECT count(*) FROM sqlite_master WHERE name='details_query_index'"), 1);
    ks_db_close(db);
}

TEST(file_reopen_and_journal)
{
    tmp_path();
    char err[128];
    struct ks_db *db = ks_db_open(path, false, err, sizeof(err));
    CHECK(db != NULL);
    char jm[32];
    CHECK_STR_EQ(ks_db_journal_mode(db, jm, sizeof(jm)), "delete");
    CHECK(ks_db_exec(db, "INSERT INTO hosts VALUES('a.example', 3)"));
    ks_db_close(db);

    db = ks_db_open(path, true, err, sizeof(err));
    CHECK(db != NULL);
    CHECK_STR_EQ(ks_db_journal_mode(db, jm, sizeof(jm)), "wal");
    CHECK_INT_EQ(ks_db_count(db, "hosts"), 1);
    CHECK_INT_EQ(ks_db_schema_version(db), KS_DB_VERSION);
    ks_db_clean(db, "hosts");
    CHECK_INT_EQ(ks_db_count(db, "hosts"), 0);
    ks_db_close(db);
    unlink(path);
    char wal[96];
    snprintf(wal, sizeof(wal), "%s-wal", path);
    unlink(wal);
    snprintf(wal, sizeof(wal), "%s-shm", path);
    unlink(wal);
}

TEST(migrates_old_rules_table)
{
    tmp_path();
    sqlite3 *h;
    CHECK(sqlite3_open(path, &h) == SQLITE_OK);
    /* a version 0 file: rules without description, nolog and created */
    CHECK(sqlite3_exec(h,
                       "create table rules (time text, node text, name text, enabled text, "
                       "precedence text, action text, duration text, operator_type text, "
                       "operator_sensitive text, operator_operand text, operator_data text, "
                       "UNIQUE(node, name));"
                       "insert into rules values ('t','n','old','True','False','allow','always',"
                       "'simple','False','process.path','/bin/x');",
                       NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(h);
    char err[128];
    struct ks_db *db = ks_db_open(path, false, err, sizeof(err));
    CHECK(db != NULL);
    CHECK_INT_EQ(ks_db_schema_version(db), KS_DB_VERSION);
    CHECK_INT_EQ(scalar(db, "SELECT count(*) FROM pragma_table_info('rules')"), 14);

    struct ks_rulesdb rdb;
    ks_rulesdb_init(&rdb);
    CHECK(ks_rulesdb_attach(&rdb, db));
    CHECK_INT_EQ((int)rdb.len, 1);
    CHECK_STR_EQ(rdb.rows[0].f[KS_RF_NAME], "old");
    CHECK_STR_EQ(rdb.rows[0].f[KS_RF_CREATED], ""); /* NULL reads as "" */
    ks_rulesdb_free(&rdb);
    ks_db_close(db);
    unlink(path);
}

static int64_t stamp_days_ago(int days, char *buf, size_t len)
{
    time_t t = time(NULL) - (time_t)days * 86400;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S.000001", &tm);
    return (int64_t)t;
}

TEST(purge_oldest_by_days)
{
    char err[128];
    struct ks_db *db = ks_db_open(NULL, false, err, sizeof(err));
    CHECK(db != NULL);
    CHECK_INT_EQ(ks_db_purge_oldest(db, 1), -1); /* empty */
    const int ages[] = {10, 5, 3, 0};
    for (size_t i = 0; i < 4; i++) {
        char ts[40], sql[256];
        stamp_days_ago(ages[i], ts, sizeof(ts));
        snprintf(sql, sizeof(sql),
                 "INSERT INTO connections (time,node,action,protocol,src_ip,src_port,dst_ip,"
                 "dst_port,uid,pid,process,process_args) VALUES ('%s','n','allow','tcp','1',"
                 "'%zu','2','80','0','1','p','a')",
                 ts, i);
        CHECK(ks_db_exec(db, sql));
    }
    char buf[64];
    CHECK(ks_db_oldest_record(db, buf, sizeof(buf)));
    CHECK(strncmp(buf, "20", 2) == 0);
    /* span is 10 days: keeping 30 does nothing, keeping 4 deletes the two oldest */
    CHECK_INT_EQ(ks_db_purge_oldest(db, 30), -1);
    CHECK_INT_EQ(ks_db_count(db, "connections"), 4);
    CHECK_INT_EQ(ks_db_purge_oldest(db, 4), 2);
    CHECK_INT_EQ(ks_db_count(db, "connections"), 2);
    /* now the span is 3 days: nothing to do for 4 */
    CHECK_INT_EQ(ks_db_purge_oldest(db, 4), -1);
    ks_db_empty_rule(db, "");
    CHECK(ks_db_exec(db, "UPDATE connections SET rule='r1'"));
    ks_db_empty_rule(db, "r1");
    CHECK_INT_EQ(ks_db_count(db, "connections"), 0);
    ks_db_close(db);
}

TEST(alerts_delete)
{
    char err[128];
    struct ks_db *db = ks_db_open(NULL, false, err, sizeof(err));
    CHECK(db != NULL);
    CHECK(ks_db_exec(db, "INSERT INTO alerts VALUES ('t1','n1','0','0','0','w','b',0),"
                         "('t1','n2','0','0','0','w','b',0)"));
    CHECK(ks_db_delete_alert(db, "t1", "n1"));
    CHECK_INT_EQ(ks_db_count(db, "alerts"), 1);
    CHECK(ks_db_delete_alert(db, "t1", NULL));
    CHECK_INT_EQ(ks_db_count(db, "alerts"), 0);
    ks_db_close(db);
}

TEST(rules_write_through)
{
    tmp_path();
    char err[128];
    struct ks_db *db = ks_db_open(path, false, err, sizeof(err));
    CHECK(db != NULL);
    struct ks_rulesdb rdb;
    ks_rulesdb_init(&rdb);
    CHECK(ks_rulesdb_attach(&rdb, db));
    ks_rulesdb_set_duration_filter(&rdb, true, 2); /* once, 30s */

    const char *v[KS_RF_COUNT] = {"2026-10-14 10:00:00", "unix:/x", "r1", "True", "False",
                                  "allow", "always", "simple", "False", "process.path",
                                  "/usr/bin/curl", "d", "False", "2026-10-14 10:00:00"};
    CHECK_INT_EQ(ks_rulesdb_add_row(&rdb, v), 0);
    v[KS_RF_NAME] = "r2";
    v[KS_RF_DURATION] = "30s"; /* filtered: not stored anywhere */
    CHECK_INT_EQ(ks_rulesdb_add_row(&rdb, v), 0);
    v[KS_RF_NAME] = "r3";
    v[KS_RF_DURATION] = "5m";
    CHECK_INT_EQ(ks_rulesdb_add_row(&rdb, v), 0);
    CHECK_INT_EQ(ks_db_count(db, "rules"), 2);

    ks_rulesdb_disable(&rdb, "unix:/x", "r3");
    CHECK_INT_EQ(scalar(db, "SELECT count(*) FROM rules WHERE name='r3' AND enabled='False'"), 1);

    /* OR REPLACE on (node, name) */
    v[KS_RF_NAME] = "r1";
    v[KS_RF_ACTION] = "deny";
    v[KS_RF_DURATION] = "always";
    CHECK_INT_EQ(ks_rulesdb_add_row(&rdb, v), 0);
    CHECK_INT_EQ(ks_db_count(db, "rules"), 2);
    ks_rulesdb_free(&rdb);
    ks_db_close(db);

    /* a new run sees them, in the order they were written */
    db = ks_db_open(path, false, err, sizeof(err));
    CHECK(db != NULL);
    ks_rulesdb_init(&rdb);
    CHECK(ks_rulesdb_attach(&rdb, db));
    CHECK_INT_EQ((int)rdb.len, 2);
    CHECK_STR_EQ(rdb.rows[0].f[KS_RF_NAME], "r3");
    CHECK_STR_EQ(rdb.rows[1].f[KS_RF_NAME], "r1");
    CHECK_STR_EQ(rdb.rows[1].f[KS_RF_ACTION], "deny");

    ks_rulesdb_set_duration_filter(&rdb, true, 3);
    ks_rulesdb_delete_filtered(&rdb); /* 5m goes */
    CHECK_INT_EQ((int)rdb.len, 1);
    CHECK_INT_EQ(ks_db_count(db, "rules"), 1);
    ks_rulesdb_delete(&rdb, "r1", NULL);
    CHECK_INT_EQ(ks_db_count(db, "rules"), 0);
    ks_rulesdb_free(&rdb);
    ks_db_close(db);
    unlink(path);
}

TEST(corrupt_file_is_refused)
{
    tmp_path();
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fputs("this is not an sqlite database, it is long enough to be read as a header....", f);
    fclose(f);
    char err[128] = "";
    struct ks_db *db = ks_db_open(path, false, err, sizeof(err));
    CHECK(db == NULL);
    CHECK(err[0] != '\0');
    unlink(path);
}

int main(void)
{
    RUN(schema_is_upstreams);
    RUN(file_reopen_and_journal);
    RUN(migrates_old_rules_table);
    RUN(purge_oldest_by_days);
    RUN(alerts_delete);
    RUN(rules_write_through);
    RUN(corrupt_file_is_refused);
    return harness_report();
}
