/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "common/strset.h"

#include "tests/harness.h"

TEST(add_and_lookup)
{
    struct ks_strset s;
    ks_strset_init(&s);
    CHECK(!ks_strset_has(&s, "a", 1));
    CHECK_INT_EQ(ks_strset_add(&s, "www.test.org", 12), 1);
    CHECK_INT_EQ(ks_strset_add(&s, "www.test.org", 12), 0);
    CHECK_INT_EQ(ks_strset_add(&s, "", 0), 1);
    CHECK(ks_strset_has(&s, "www.test.org", 12));
    CHECK(ks_strset_has(&s, "", 0));
    CHECK(!ks_strset_has(&s, "www.test.or", 11));
    CHECK(!ks_strset_has(&s, "www.test.org2", 13));
    /* Lengths matter, not NUL terminators. */
    CHECK_INT_EQ(ks_strset_add(&s, "a\0b", 3), 1);
    CHECK(ks_strset_has(&s, "a\0b", 3));
    CHECK(!ks_strset_has(&s, "a", 1));
    CHECK_INT_EQ(s.count, 3);
    ks_strset_clear(&s);
    CHECK_INT_EQ(s.count, 0);
    CHECK(!ks_strset_has(&s, "", 0));
    ks_strset_clear(&s);
}

TEST(many_entries)
{
    struct ks_strset s;
    char buf[32];
    ks_strset_init(&s);
    for (int i = 0; i < 200000; i++) {
        int n = snprintf(buf, sizeof(buf), "host%d.example.com", i);
        CHECK(ks_strset_add(&s, buf, (size_t)n) == 1);
    }
    CHECK_INT_EQ(s.count, 200000);
    for (int i = 0; i < 200000; i += 7) {
        int n = snprintf(buf, sizeof(buf), "host%d.example.com", i);
        CHECK(ks_strset_has(&s, buf, (size_t)n));
        CHECK(ks_strset_add(&s, buf, (size_t)n) == 0);
    }
    CHECK(!ks_strset_has(&s, "host200000.example.com", 22));
    ks_strset_clear(&s);
}

int main(void)
{
    RUN(add_and_lookup);
    RUN(many_entries);
    return harness_report();
}
