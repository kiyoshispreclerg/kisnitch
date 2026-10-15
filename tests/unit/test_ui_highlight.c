/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/highlight.c against the default configurations of upstream.
 */
#include "ui/highlight.h"

#include <string.h>

#include "tests/harness.h"

TEST(common)
{
    struct ks_hl_style s;
    CHECK(ks_highlight(KS_HL_COMMON, 2, "allow", &s));
    CHECK_STR_EQ(s.color, "#008000");
    CHECK(s.center);
    CHECK(ks_highlight(KS_HL_COMMON, 1, "deny", &s));
    CHECK_STR_EQ(s.color, "#ff0000");
    CHECK(ks_highlight(KS_HL_COMMON, 3, "reject", &s));
    CHECK_STR_EQ(s.color, "#800080");
    CHECK(ks_highlight(KS_HL_COMMON, 2, "\xe2\x9c\x93 online", &s));
    CHECK_STR_EQ(s.color, "#008000");
    CHECK(ks_highlight(KS_HL_COMMON, 2, "\xe2\x98\x93 offline", &s));
    CHECK_STR_EQ(s.color, "#ff0000");
    /* other columns and other texts are left alone; matching is exact */
    CHECK(!ks_highlight(KS_HL_COMMON, 0, "allow", &s));
    CHECK(!ks_highlight(KS_HL_COMMON, 4, "allow", &s));
    CHECK(!ks_highlight(KS_HL_COMMON, 2, "Allow", &s));
    CHECK(!ks_highlight(KS_HL_COMMON, 2, "allowed", &s));
}

TEST(rules_netstat_fw)
{
    struct ks_hl_style s;
    CHECK(ks_highlight(KS_HL_RULES, 3, "True", &s));
    CHECK_STR_EQ(s.color, "#008000");
    CHECK(ks_highlight(KS_HL_RULES, 4, "deny", &s));
    CHECK_STR_EQ(s.color, "#ff0000");
    CHECK(!ks_highlight(KS_HL_RULES, 2, "True", &s));
    CHECK(ks_highlight(KS_HL_NETSTAT, 2, "LISTEN", &s));
    CHECK_STR_EQ(s.color, "#008000");
    CHECK(ks_highlight(KS_HL_NETSTAT, 2, "Established", &s));
    CHECK_STR_EQ(s.color, "#0000ff");
    /* the intermediate TCP states: matched, no color of their own */
    CHECK(ks_highlight(KS_HL_NETSTAT, 2, "TCP_TIME_WAIT", &s));
    CHECK(s.color == NULL);
    CHECK(s.center);
    CHECK(ks_highlight(KS_HL_FW, 7, "drop", &s));
    CHECK_STR_EQ(s.color, "#ff0000");
    CHECK(ks_highlight(KS_HL_FW, 10, "return", &s));
    CHECK_STR_EQ(s.color, "#800080");
    CHECK(!ks_highlight(KS_HL_NONE, 2, "allow", &s));
}

TEST(per_tab)
{
    CHECK_INT_EQ(ks_highlight_for_tab(KS_TAB_MAIN), KS_HL_COMMON);
    CHECK_INT_EQ(ks_highlight_for_tab(KS_TAB_NODES), KS_HL_COMMON);
    CHECK_INT_EQ(ks_highlight_for_tab(KS_TAB_HOSTS), KS_HL_COMMON);
    CHECK_INT_EQ(ks_highlight_for_tab(KS_TAB_RULES), KS_HL_RULES);
    CHECK_INT_EQ(ks_highlight_for_tab(KS_TAB_ALERTS), KS_HL_RULES);
    CHECK_INT_EQ(ks_highlight_for_tab(KS_TAB_FIREWALL), KS_HL_FW);
    CHECK_INT_EQ(ks_highlight_for_tab(KS_TAB_NETSTAT), KS_HL_NETSTAT);
}

int main(void)
{
    RUN(common);
    RUN(rules_netstat_fw);
    RUN(per_tab);
    return harness_report();
}
