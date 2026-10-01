/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Expected values follow Go's strings.ToLower, strings.EqualFold and
 * utf8.DecodeRuneInString.
 */
#include "common/unicode.h"

#include <stdlib.h>

#include "tests/harness.h"

TEST(decode)
{
    uint32_t r;
    CHECK_INT_EQ(ks_utf8_decode("a", 1, &r), 1);
    CHECK_INT_EQ(r, 'a');
    CHECK_INT_EQ(ks_utf8_decode("\xc3\xa9", 2, &r), 2);
    CHECK_INT_EQ(r, 0xE9);
    CHECK_INT_EQ(ks_utf8_decode("\xe2\x82\xac", 3, &r), 3);
    CHECK_INT_EQ(r, 0x20AC);
    CHECK_INT_EQ(ks_utf8_decode("\xf0\x9f\x98\x80", 4, &r), 4);
    CHECK_INT_EQ(r, 0x1F600);
    /* invalid: lone continuation, overlong, surrogate, truncated, > U+10FFFF */
    static const char *const bad[] = {"\x80", "\xc0\xaf", "\xed\xa0\x80",
                                      "\xe2\x82", "\xf4\x90\x80\x80", "\xff"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK_INT_EQ(ks_utf8_decode(bad[i], strlen(bad[i]), &r), 1);
        CHECK_INT_EQ(r, KS_RUNE_ERROR);
    }
}

static const char *lower(const char *s)
{
    static char buf[256];
    char *l = ks_str_to_lower(s);
    snprintf(buf, sizeof(buf), "%s", l ? l : "(null)");
    free(l);
    return buf;
}

TEST(to_lower)
{
    CHECK_STR_EQ(lower("/USR/BiN/OpenSnitchd"), "/usr/bin/opensnitchd");
    CHECK_STR_EQ(lower(""), "");
    CHECK_STR_EQ(lower("^/TMP/CURL$\\D"), "^/tmp/curl$\\d");
    CHECK_STR_EQ(lower("\xc3\x89T\xc3\x89"), "\xc3\xa9t\xc3\xa9");         /* ÉTÉ */
    CHECK_STR_EQ(lower("\xce\xa3\xce\x91"), "\xcf\x83\xce\xb1");           /* ΣΑ */
    CHECK_STR_EQ(lower("\xe2\x84\xaa"), "k");                              /* Kelvin */
    /* Invalid bytes become U+FFFD (only when the string isn't pure ASCII). */
    CHECK_STR_EQ(lower("A\xff\xc3\x89"), "a\xef\xbf\xbd\xc3\xa9");
}

TEST(equal_fold)
{
    CHECK(ks_str_equal_fold("opensnitch.io", "OpEnsNitCh.io"));
    CHECK(ks_str_equal_fold("", ""));
    CHECK(!ks_str_equal_fold("a", ""));
    CHECK(!ks_str_equal_fold("www.opensnitch.io", "opensnitch.io"));
    CHECK(ks_str_equal_fold("\xc3\xa9t\xc3\xa9", "\xc3\x89T\xc3\x89"));
    CHECK(ks_str_equal_fold("k", "\xe2\x84\xaa"));  /* Kelvin sign */
    CHECK(ks_str_equal_fold("\xcf\x83", "\xce\xa3"));
    CHECK(ks_str_equal_fold("\xcf\x82", "\xce\xa3")); /* final sigma */
    CHECK(!ks_str_equal_fold("a", "b"));
    CHECK(!ks_str_equal_fold("abc", "abd"));
}

int main(void)
{
    RUN(decode);
    RUN(to_lower);
    RUN(equal_fold);
    return harness_report();
}
