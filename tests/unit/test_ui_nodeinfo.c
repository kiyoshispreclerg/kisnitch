/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/nodeinfo.c: the texts of the node panel, as upstream's Python formats
 * them (the expected strings were produced by running its _update_node_info
 * arithmetic).
 */
#include "ui/nodeinfo.h"

#include <string.h>

#include "tests/harness.h"

TEST(bytes)
{
    char b[32];
    ks_nodeinfo_bytes(0, b, sizeof(b));
    CHECK_STR_EQ(b, "0 B");
    ks_nodeinfo_bytes(500, b, sizeof(b)); /* never "B" above 0: upstream divides first */
    CHECK_STR_EQ(b, "0 KB");
    ks_nodeinfo_bytes(1024, b, sizeof(b));
    CHECK_STR_EQ(b, "1 KB");
    ks_nodeinfo_bytes(8589934592.0, b, sizeof(b));
    CHECK_STR_EQ(b, "8 GB");
    ks_nodeinfo_bytes(16651239424.0, b, sizeof(b));
    CHECK_STR_EQ(b, "16 GB");
    ks_nodeinfo_bytes(2621440.0, b, sizeof(b)); /* 2.5 MB: half to even */
    CHECK_STR_EQ(b, "2 MB");
    ks_nodeinfo_bytes(3670016.0, b, sizeof(b)); /* 3.5 MB */
    CHECK_STR_EQ(b, "4 MB");
}

TEST(uptime)
{
    char b[96];
    ks_nodeinfo_uptime(0, b, sizeof(b));
    CHECK_STR_EQ(b, "<b>System uptime:</b> 0h 0m");
    /* any uptime above 0 takes the "days" form, with days rounded */
    ks_nodeinfo_uptime(3600 * 5 + 60 * 7, b, sizeof(b));
    CHECK_STR_EQ(b, "<b>System uptime:</b> 0 days 5h 7m");
    ks_nodeinfo_uptime(86400 * 3 + 3600 * 14, b, sizeof(b));
    CHECK_STR_EQ(b, "<b>System uptime:</b> 4 days 14h 0m"); /* 3.58 days */
    ks_nodeinfo_uptime(86400 * 2, b, sizeof(b));
    CHECK_STR_EQ(b, "<b>System uptime:</b> 2 days 0h 0m");
}

TEST(parse)
{
    struct ks_nodeinfo n;
    const char *json =
        "{\"Uptime\": 360000, \"Loads\": [12345, 54321, 100000], \"Totalram\": 16651239424, "
        "\"Freeram\": 8000000000, \"Sharedram\": 0, \"Bufferram\": 1, \"Totalswap\": 2147479552, "
        "\"Freeswap\": 2147479552, \"Procs\": 512, \"Totalhigh\": 0, \"Freehigh\": 0, \"Unit\": 1}";
    CHECK(ks_nodeinfo_parse(json, &n));
    CHECK_STR_EQ(n.ram, "<b>RAM:</b> 16 GB <b>Free:</b> 7 GB");
    CHECK_STR_EQ(n.swap, "<b>Swap:</b> 2 GB <b>Free:</b> 2 GB");
    CHECK_STR_EQ(n.procs, "<b>Processes:</b> 512");
    CHECK_STR_EQ(n.loadavg, "<b>Load avg:</b> 0.12, 0.54, 1.00");
    CHECK_STR_EQ(n.uptime, "<b>System uptime:</b> 4 days 4h 0m");
    CHECK_INT_EQ(n.ram_max, 16651239);
    CHECK_INT_EQ(n.ram_value, 8651239);
    /* no swap used: value 0 -> maximum 1 */
    CHECK_INT_EQ(n.swap_value, 0);
    CHECK_INT_EQ(n.swap_max, 1);

    CHECK(!ks_nodeinfo_parse("not json", &n));
    CHECK(!ks_nodeinfo_parse("{\"Uptime\": 1}", &n));
    CHECK(!ks_nodeinfo_parse("[1,2]", &n));
}

int main(void)
{
    RUN(bytes);
    RUN(uptime);
    RUN(parse);
    return harness_report();
}
