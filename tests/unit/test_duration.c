/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Vectors from Go's src/time/time_test.go (parseDurationTests and
 * parseDurationErrorTests), which upstream relies on through
 * time.ParseDuration.
 */
#include "common/duration.h"

#include "tests/harness.h"

#define S KS_SECOND
#define MS KS_MILLISECOND
#define US KS_MICROSECOND
#define M KS_MINUTE
#define H KS_HOUR

static const struct {
    const char *in;
    int64_t want;
} valid[] = {
    /* simple */
    {"0", 0},
    {"5s", 5 * S},
    {"30s", 30 * S},
    {"1478s", 1478 * S},
    /* sign */
    {"-5s", -5 * S},
    {"+5s", 5 * S},
    {"-0", 0},
    {"+0", 0},
    /* decimal */
    {"5.0s", 5 * S},
    {"5.6s", 5 * S + 600 * MS},
    {"5.s", 5 * S},
    {".5s", 500 * MS},
    {"1.0s", 1 * S},
    {"1.00s", 1 * S},
    {"1.004s", 1 * S + 4 * MS},
    {"1.0040s", 1 * S + 4 * MS},
    {"100.00100s", 100 * S + 1 * MS},
    /* different units */
    {"10ns", 10},
    {"11us", 11 * US},
    {"12\xc2\xb5s", 12 * US}, /* U+00B5 */
    {"12\xce\xbcs", 12 * US}, /* U+03BC */
    {"13ms", 13 * MS},
    {"14s", 14 * S},
    {"15m", 15 * M},
    {"16h", 16 * H},
    /* composite durations */
    {"3h30m", 3 * H + 30 * M},
    {"10.5s4m", 4 * M + 10 * S + 500 * MS},
    {"-2m3.4s", -(2 * M + 3 * S + 400 * MS)},
    {"1h2m3s4ms5us6ns", 1 * H + 2 * M + 3 * S + 4 * MS + 5 * US + 6},
    {"39h9m14.425s", 39 * H + 9 * M + 14 * S + 425 * MS},
    /* large value */
    {"52763797000ns", INT64_C(52763797000)},
    /* more than 9 digits after decimal point (golang.org/issue/6617) */
    {"0.3333333333333333333h", 20 * M},
    /* 1<<53+1 cannot be stored precisely in a float64 */
    {"9007199254740993ns", INT64_C(9007199254740993)},
    /* largest duration that can be represented by int64 in nanoseconds */
    {"9223372036854775807ns", INT64_MAX},
    {"9223372036854775.807us", INT64_MAX},
    {"9223372036s854ms775us807ns", INT64_MAX},
    {"-9223372036854775808ns", INT64_MIN},
    {"-9223372036854775.808us", INT64_MIN},
    {"-9223372036s854ms775us808ns", INT64_MIN},
    /* largest negative round trip value (golang.org/issue/48629) */
    {"-2562047h47m16.854775808s", INT64_MIN},
    /* huge string (golang.org/issue/15011) */
    {"0.100000000000000000000h", 6 * M},
    /* first overflow check in leadingFraction */
    {"0.830103483285477580700h", 49 * M + 48 * S + 372539827},
    /* durations seen in upstream configs and rules */
    {"15s", 15 * S},
    {"25s", 25 * S},
    {"12h", 12 * H},
    {"24h", 24 * H},
};

static const struct {
    const char *in;
    const char *err;
} invalid[] = {
    {"", "time: invalid duration \"\""},
    {"3", "time: missing unit in duration \"3\""},
    {"-", "time: invalid duration \"-\""},
    {"s", "time: invalid duration \"s\""},
    {".", "time: invalid duration \".\""},
    {"-.", "time: invalid duration \"-.\""},
    {".s", "time: invalid duration \".s\""},
    {"+.s", "time: invalid duration \"+.s\""},
    {"1d", "time: unknown unit \"d\" in duration \"1d\""},
    {"\x85\x85", "time: invalid duration \"\x85\x85\""},
    {"\xff" "ff", "time: invalid duration \"\xff" "ff\""},
    {"hello \xff" "ff world", "time: invalid duration \"hello \xff" "ff world\""},
    /* overflow */
    {"9223372036854775810ns", "time: invalid duration \"9223372036854775810ns\""},
    {"9223372036854775808ns", "time: invalid duration \"9223372036854775808ns\""},
    {"9223372036854775.808us", "time: invalid duration \"9223372036854775.808us\""},
    {"9223372036854ms775us808ns", "time: invalid duration \"9223372036854ms775us808ns\""},
    {"-9223372036854775809ns", "time: invalid duration \"-9223372036854775809ns\""},
    /* rule keywords are not durations */
    {"once", "time: invalid duration \"once\""},
    {"until restart", "time: invalid duration \"until restart\""},
};

TEST(valid_durations)
{
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        int64_t got = 12345;
        char err[128] = "";
        int rc = ks_parse_duration(valid[i].in, &got, err, sizeof(err));
        CHECK_MSG(rc == 0, "\"%s\": unexpected error: %s", valid[i].in, err);
        CHECK_MSG(got == valid[i].want, "\"%s\": got %" PRId64 ", want %" PRId64,
                  valid[i].in, got, valid[i].want);
    }
}

TEST(invalid_durations)
{
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        int64_t got = 0;
        char err[128] = "";
        int rc = ks_parse_duration(invalid[i].in, &got, err, sizeof(err));
        CHECK_MSG(rc == -1, "\"%s\": expected an error", invalid[i].in);
        CHECK_STR_EQ(err, invalid[i].err);
    }
}

TEST(null_error_buffer_is_allowed)
{
    int64_t got;
    CHECK(ks_parse_duration("bogus", &got, NULL, 0) == -1);
}

TEST(error_message_is_truncated_safely)
{
    int64_t got;
    char err[8];
    CHECK(ks_parse_duration("1d", &got, err, sizeof(err)) == -1);
    CHECK_INT_EQ(strlen(err), sizeof(err) - 1);
}

TEST(rule_duration_kinds)
{
    CHECK(ks_rule_duration_kind("once") == KS_RULE_ONCE);
    CHECK(ks_rule_duration_kind("until restart") == KS_RULE_UNTIL_RESTART);
    CHECK(ks_rule_duration_kind("always") == KS_RULE_ALWAYS);
    CHECK(ks_rule_duration_kind("30s") == KS_RULE_TEMPORARY);
    CHECK(ks_rule_duration_kind("1h") == KS_RULE_TEMPORARY);
    /* Upstream compares verbatim: anything else is "temporary". */
    CHECK(ks_rule_duration_kind("Once") == KS_RULE_TEMPORARY);
    CHECK(ks_rule_duration_kind("") == KS_RULE_TEMPORARY);
}

/* Go's time_test.go durationTests. */
TEST(format_durations)
{
    static const struct {
        const char *str;
        int64_t d;
    } cases[] = {
        {"0s", 0},
        {"1ns", 1 * KS_NANOSECOND},
        {"1.1\xc2\xb5s", 1100 * KS_NANOSECOND},
        {"2.2ms", 2200 * KS_MICROSECOND},
        {"3.3s", 3300 * KS_MILLISECOND},
        {"4m5s", 4 * KS_MINUTE + 5 * KS_SECOND},
        {"4m5.001s", 4 * KS_MINUTE + 5001 * KS_MILLISECOND},
        {"5h6m7.001s", 5 * KS_HOUR + 6 * KS_MINUTE + 7001 * KS_MILLISECOND},
        {"8m0.000000001s", 8 * KS_MINUTE + 1 * KS_NANOSECOND},
        {"2562047h47m16.854775807s", INT64_MAX},
        {"-2562047h47m16.854775808s", INT64_MIN},
        {"-1.5s", -1500 * KS_MILLISECOND},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char buf[KS_DURATION_STRLEN];
        ks_format_duration(cases[i].d, buf, sizeof(buf));
        CHECK_STR_EQ(buf, cases[i].str);
    }
}

int main(void)
{
    RUN(format_durations);
    RUN(valid_durations);
    RUN(invalid_durations);
    RUN(null_error_buffer_is_allowed);
    RUN(error_message_is_truncated_safely);
    RUN(rule_duration_kinds);
    return harness_report();
}
