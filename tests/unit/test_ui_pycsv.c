/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/pycsv.c against what Python's csv.writer wrote for the same rows.
 */
#include "ui/pycsv.h"

#include "tests/harness.h"

TEST(rows)
{
    GString *g = g_string_new(NULL);
    const char *r1[] = {"a", "b c", "d,e", "q\"x", "l1\nl2", ""};
    const char *r2[] = {""};
    const char *r3[] = {"x"};
    ks_pycsv_row(g, r1, 6);
    ks_pycsv_row(g, r2, 1);
    ks_pycsv_row(g, r3, 1);
    CHECK_STR_EQ(g->str, "a,b c,\"d,e\",\"q\"\"x\",\"l1\nl2\",\r\n\"\"\r\nx\r\n");
    g_string_free(g, TRUE);
}

int main(void)
{
    RUN(rows);
    return harness_report();
}
