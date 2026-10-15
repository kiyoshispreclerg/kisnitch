/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See qmodel.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/qmodel.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>

struct ks_qmodel {
    sqlite3 *h;
    ks_qmodel_map_fn map;
    char *sql;
    int ncols;
    char **colnames;
    int64_t nrows;
    /* the cached page */
    int64_t first;
    int npage;
    char **cells; /* npage * ncols */
};

struct ks_qmodel *ks_qmodel_new(sqlite3 *h)
{
    struct ks_qmodel *m = calloc(1, sizeof(*m));
    if (m != NULL)
        m->h = h;
    return m;
}

void ks_qmodel_set_mapper(struct ks_qmodel *m, ks_qmodel_map_fn fn)
{
    m->map = fn;
}

static void drop_page(struct ks_qmodel *m)
{
    for (int i = 0; i < m->npage * m->ncols; i++)
        g_free(m->cells[i]);
    free(m->cells);
    m->cells = NULL;
    m->npage = 0;
    m->first = 0;
}

static void drop_cols(struct ks_qmodel *m)
{
    for (int i = 0; i < m->ncols; i++)
        g_free(m->colnames[i]);
    free(m->colnames);
    m->colnames = NULL;
    m->ncols = 0;
}

void ks_qmodel_free(struct ks_qmodel *m)
{
    if (m == NULL)
        return;
    drop_page(m);
    drop_cols(m);
    g_free(m->sql);
    free(m);
}

const char *ks_qmodel_query(const struct ks_qmodel *m)
{
    return m->sql != NULL ? m->sql : "";
}

int64_t ks_qmodel_rows(const struct ks_qmodel *m)
{
    return m->nrows;
}

int ks_qmodel_cols(const struct ks_qmodel *m)
{
    return m->ncols;
}

const char *ks_qmodel_colname(const struct ks_qmodel *m, int col)
{
    return col >= 0 && col < m->ncols ? m->colnames[col] : "";
}

bool ks_qmodel_set_query(struct ks_qmodel *m, const char *sql)
{
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(m->h, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int ncols = sqlite3_column_count(st);
    char **names = calloc(ncols > 0 ? (size_t)ncols : 1, sizeof(*names));
    if (names == NULL) {
        sqlite3_finalize(st);
        return false;
    }
    for (int i = 0; i < ncols; i++)
        names[i] = g_strdup(sqlite3_column_name(st, i));
    sqlite3_finalize(st);

    char *cq = g_strdup_printf("SELECT count(*) FROM (%s)", sql);
    int64_t n = 0;
    bool ok = sqlite3_prepare_v2(m->h, cq, -1, &st, NULL) == SQLITE_OK;
    g_free(cq);
    if (ok) {
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    if (!ok) {
        for (int i = 0; i < ncols; i++)
            g_free(names[i]);
        free(names);
        return false;
    }
    drop_page(m);
    drop_cols(m);
    m->colnames = names;
    m->ncols = ncols;
    m->nrows = n;
    if (m->sql != sql) {
        char *copy = g_strdup(sql);
        g_free(m->sql);
        m->sql = copy;
    }
    return true;
}

bool ks_qmodel_refresh(struct ks_qmodel *m)
{
    if (m->sql == NULL)
        return false;
    char *sql = g_strdup(m->sql);
    bool ok = ks_qmodel_set_query(m, sql);
    g_free(sql);
    return ok;
}

static void load_page(struct ks_qmodel *m, int64_t first)
{
    drop_page(m);
    m->first = first;
    char *q = g_strdup_printf("SELECT * FROM (%s) LIMIT %d OFFSET %lld", m->sql,
                              KS_QMODEL_PAGE, (long long)first);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(m->h, q, -1, &st, NULL) != SQLITE_OK) {
        g_free(q);
        return;
    }
    g_free(q);
    m->cells = calloc((size_t)KS_QMODEL_PAGE * (size_t)(m->ncols > 0 ? m->ncols : 1),
                      sizeof(*m->cells));
    if (m->cells == NULL) {
        sqlite3_finalize(st);
        return;
    }
    while (m->npage < KS_QMODEL_PAGE && sqlite3_step(st) == SQLITE_ROW) {
        for (int c = 0; c < m->ncols; c++) {
            const char *t = (const char *)sqlite3_column_text(st, c);
            const char *shown = t != NULL ? t : "";
            if (m->map != NULL)
                shown = m->map(c, shown);
            m->cells[(size_t)m->npage * (size_t)m->ncols + (size_t)c] = g_strdup(shown);
        }
        m->npage++;
    }
    sqlite3_finalize(st);
}

const char *ks_qmodel_cell(struct ks_qmodel *m, int64_t row, int col)
{
    if (m->sql == NULL || row < 0 || row >= m->nrows || col < 0 || col >= m->ncols)
        return "";
    if (m->cells == NULL || row < m->first || row >= m->first + m->npage) {
        /* center the page on the row so scrolling either way is a hit */
        int64_t first = row - KS_QMODEL_PAGE / 4;
        load_page(m, first < 0 ? 0 : first);
        if (row < m->first || row >= m->first + m->npage)
            return "";
    }
    const char *c = m->cells[(size_t)(row - m->first) * (size_t)m->ncols + (size_t)col];
    return c != NULL ? c : "";
}

void ks_qmodel_foreach(const struct ks_qmodel *m, int64_t first, int64_t max, ks_qmodel_row_fn fn,
                       void *ud)
{
    if (m->sql == NULL)
        return;
    char *q;
    if (max >= 0)
        q = g_strdup_printf("SELECT * FROM (%s) LIMIT %lld OFFSET %lld", m->sql, (long long)max,
                            (long long)first);
    else
        q = g_strdup_printf("SELECT * FROM (%s) LIMIT -1 OFFSET %lld", m->sql, (long long)first);
    sqlite3_stmt *st;
    int rc = sqlite3_prepare_v2(m->h, q, -1, &st, NULL);
    g_free(q);
    if (rc != SQLITE_OK)
        return;
    const char **cells = calloc(m->ncols > 0 ? (size_t)m->ncols : 1, sizeof(*cells));
    if (cells == NULL) {
        sqlite3_finalize(st);
        return;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        for (int c = 0; c < m->ncols; c++) {
            const char *t = (const char *)sqlite3_column_text(st, c);
            cells[c] = t != NULL ? t : "";
        }
        if (!fn(cells, m->ncols, ud))
            break;
    }
    free(cells);
    sqlite3_finalize(st);
}
