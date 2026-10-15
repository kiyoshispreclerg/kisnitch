/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/qmodel.c: 100 000 events behind a window of rows.
 */
#include "ui/qmodel.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ui/db.h"
#include "ui/statsq.h"
#include "tests/harness.h"

#define N 100000

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static struct ks_db *fill(int n)
{
    char err[128];
    struct ks_db *db = ks_db_open(NULL, false, err, sizeof(err));
    sqlite3 *h = ks_db_handle(db);
    sqlite3_exec(h, "BEGIN", NULL, NULL, NULL);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(h,
                       "INSERT INTO connections (time,node,action,protocol,src_ip,src_port,"
                       "dst_ip,dst_host,dst_port,uid,pid,process,process_args,process_cwd,rule) "
                       "VALUES (?,'unix:/local',?,'tcp','10.0.0.2',?,'1.1.1.1','h.example','443',"
                       "'0','1','/bin/x','a','/','r')",
                       -1, &st, NULL);
    for (int i = 0; i < n; i++) {
        char t[40], sp[16];
        snprintf(t, sizeof(t), "2026-01-01 00:00:00.%06d", i);
        /* distinct src_port keeps the UNIQUE constraint from merging rows */
        snprintf(sp, sizeof(sp), "%d", i);
        sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, i % 3 == 0 ? "deny" : "allow", -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 3, sp, -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    sqlite3_exec(h, "COMMIT", NULL, NULL, NULL);
    return db;
}

TEST(hundred_thousand_rows)
{
    struct ks_db *db = fill(N);
    CHECK_INT_EQ((int)ks_db_count(db, "connections"), N);
    struct ks_qmodel *m = ks_qmodel_new(ks_db_handle(db));

    char *q = ks_sq_list(KS_TAB_MAIN, "", 0, "1", 1, 4); /* all, newest first */
    double t0 = now_ms();
    CHECK(ks_qmodel_set_query(m, q));
    double t_set = now_ms() - t0;
    free(q);
    CHECK_INT_EQ((int)ks_qmodel_rows(m), N);
    CHECK_INT_EQ(ks_qmodel_cols(m), 14);
    CHECK_STR_EQ(ks_qmodel_colname(m, 0), "Time");

    /* newest first: row 0 is the last inserted */
    CHECK_STR_EQ(ks_qmodel_cell(m, 0, 0), "2026-01-01 00:00:00.099999");
    CHECK_STR_EQ(ks_qmodel_cell(m, N - 1, 0), "2026-01-01 00:00:00.000000");
    CHECK_STR_EQ(ks_qmodel_cell(m, 50000, 0), "2026-01-01 00:00:00.049999");
    CHECK_STR_EQ(ks_qmodel_cell(m, 50001, 3), "49998");
    CHECK_STR_EQ(ks_qmodel_cell(m, N, 0), "");
    CHECK_STR_EQ(ks_qmodel_cell(m, -1, 0), "");

    /* scrolling: a screenful of rows, from the top, the middle, the end */
    t0 = now_ms();
    for (int base = 0; base < N; base += 25000) {
        for (int r = base; r < base + 60; r++)
            (void)ks_qmodel_cell(m, r, 0);
    }
    for (int r = N - 60; r < N; r++)
        (void)ks_qmodel_cell(m, r, 11);
    double t_scroll = now_ms() - t0;
    fprintf(stderr, "  100000 rows: set_query %.1f ms, 5 screens %.1f ms\n", t_set, t_scroll);
    CHECK(t_set < 2000.0);
    CHECK(t_scroll < 2000.0);

    /* a filter shrinks it */
    q = ks_sq_list(KS_TAB_MAIN, "", 1, "1", 1, 4); /* allow */
    CHECK(ks_qmodel_set_query(m, q));
    free(q);
    CHECK_INT_EQ((int)ks_qmodel_rows(m), N - (N + 2) / 3);
    /* a LIMIT is part of the query */
    q = ks_sq_list(KS_TAB_MAIN, "", 0, "1", 1, 0);
    CHECK(ks_qmodel_set_query(m, q));
    free(q);
    CHECK_INT_EQ((int)ks_qmodel_rows(m), 50);
    CHECK_STR_EQ(ks_qmodel_cell(m, 49, 0), "2026-01-01 00:00:00.099950");

    /* a bad query leaves the old one */
    CHECK(!ks_qmodel_set_query(m, "SELECT nope FROM nowhere"));
    CHECK_INT_EQ((int)ks_qmodel_rows(m), 50);

    /* more data and refresh */
    ks_db_exec(db, "DELETE FROM connections WHERE CAST(src_port AS INTEGER) < 99000");
    CHECK(ks_qmodel_refresh(m));
    CHECK_INT_EQ((int)ks_qmodel_rows(m), 50);
    CHECK_STR_EQ(ks_qmodel_cell(m, 0, 0), "2026-01-01 00:00:00.099999");

    ks_qmodel_free(m);
    ks_db_close(db);
}

static bool count_rows(const char *const *cells, int n, void *ud)
{
    (void)cells;
    (void)n;
    return ++*(int *)ud < 10;
}

TEST(foreach_stops)
{
    struct ks_db *db = fill(100);
    struct ks_qmodel *m = ks_qmodel_new(ks_db_handle(db));
    CHECK(ks_qmodel_set_query(m, "SELECT time, action FROM connections ORDER BY 1"));
    int n = 0;
    ks_qmodel_foreach(m, 0, -1, count_rows, &n);
    CHECK_INT_EQ(n, 10);
    n = 0;
    ks_qmodel_foreach(m, 95, -1, count_rows, &n);
    CHECK_INT_EQ(n, 5);
    ks_qmodel_free(m);
    ks_db_close(db);
}

int main(void)
{
    RUN(hundred_thousand_rows);
    RUN(foreach_stops);
    return harness_report();
}
