/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Python's csv.writer(stream, delimiter=',').writerows(rows): what Ctrl+C
 * puts on the clipboard in the statistics window (_copy_selected_rows).
 * Quoting is QUOTE_MINIMAL: a field is quoted if it has a comma, a double
 * quote, CR or LF (or if it is the empty only field of a row); quotes are
 * doubled; rows end in "\r\n".
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: the result is a malloc'd string owned by the caller.
 */
#ifndef KS_UI_PYCSV_H
#define KS_UI_PYCSV_H

/* One row of `n` fields, appended to `out` (a GString). */
#include <glib.h>
void ks_pycsv_row(GString *out, const char *const *fields, int n);

#endif
