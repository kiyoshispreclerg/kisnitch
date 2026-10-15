/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A read-only window onto the result of a SELECT, for tables with
 * hundreds of thousands of rows. Port of the idea of upstream
 * ui/opensnitch/customwidgets/generictableview.py (GenericTableModel: run
 * the query, count its rows, and fill only what the viewport shows): the
 * rows are not read up front; the cell of a row loads the page of
 * KS_QMODEL_PAGE rows around it (LIMIT/OFFSET), and one page is kept.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_qmodel owns the query text, column names and the
 * cached page; strings returned by ks_qmodel_cell() are valid until the
 * next call to ks_qmodel_cell() or ks_qmodel_set_query(). It borrows the
 * sqlite3 handle.
 */
#ifndef KS_UI_QMODEL_H
#define KS_UI_QMODEL_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

#define KS_QMODEL_PAGE 256

struct ks_qmodel;

/* How a cell is shown, when it is not what the table holds (the Netstat
 * table's state, protocol and family are numbers there). Returns the text
 * to show, valid until the next call. */
typedef const char *(*ks_qmodel_map_fn)(int col, const char *text);

struct ks_qmodel *ks_qmodel_new(sqlite3 *h);
void ks_qmodel_set_mapper(struct ks_qmodel *m, ks_qmodel_map_fn fn);
void ks_qmodel_free(struct ks_qmodel *m);

/* Runs `sql`: counts its rows and reads its column names. The previous
 * query stays if this one fails (false). The columns can change. */
bool ks_qmodel_set_query(struct ks_qmodel *m, const char *sql);
/* GenericTableModel.lastQuery() */
const char *ks_qmodel_query(const struct ks_qmodel *m);
/* Runs the same query again (the data changed); true if the number of
 * rows or any cell may have changed. */
bool ks_qmodel_refresh(struct ks_qmodel *m);

int64_t ks_qmodel_rows(const struct ks_qmodel *m);
int ks_qmodel_cols(const struct ks_qmodel *m);
const char *ks_qmodel_colname(const struct ks_qmodel *m, int col);
/* The cell as text ("" for NULL, "" out of range). */
const char *ks_qmodel_cell(struct ks_qmodel *m, int64_t row, int col);

/* Walks the rows of the whole query, for export and copy: calls `fn` with
 * the cells of each row until it returns false. Does not touch the page
 * cache. */
typedef bool (*ks_qmodel_row_fn)(const char *const *cells, int ncols, void *ud);
void ks_qmodel_foreach(const struct ks_qmodel *m, int64_t first, int64_t max,
                       ks_qmodel_row_fn fn, void *ud);

#endif
