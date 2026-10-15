/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See pycsv.h.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/pycsv.h"

#include <glib.h>
#include <stdbool.h>
#include <string.h>

void ks_pycsv_row(GString *out, const char *const *fields, int n)
{
    for (int i = 0; i < n; i++) {
        const char *f = fields[i] != NULL ? fields[i] : "";
        if (i > 0)
            g_string_append_c(out, ',');
        bool quote = strpbrk(f, ",\"\r\n") != NULL || (f[0] == '\0' && n == 1);
        if (!quote) {
            g_string_append(out, f);
            continue;
        }
        g_string_append_c(out, '"');
        for (const char *p = f; *p; p++) {
            if (*p == '"')
                g_string_append_c(out, '"');
            g_string_append_c(out, *p);
        }
        g_string_append_c(out, '"');
    }
    g_string_append(out, "\r\n");
}
