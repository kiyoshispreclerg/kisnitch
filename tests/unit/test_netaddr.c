/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Expected values follow Go's net and net/netip packages.
 */
#include "common/netaddr.h"

#include "tests/harness.h"

static const char *ipstr(const char *in)
{
    static char buf[KS_IP_STRLEN];
    struct ks_ip ip;
    if (ks_ip_parse(in, &ip) < 0)
        return "PARSE-ERROR";
    ks_ip_string(&ip, buf, sizeof(buf));
    return buf;
}

TEST(parse_ip_and_string)
{
    static const struct {
        const char *in, *out;
    } cases[] = {
        {"127.0.0.1", "127.0.0.1"},
        {"185.53.178.14", "185.53.178.14"},
        {"0.0.0.0", "0.0.0.0"},
        {"255.255.255.255", "255.255.255.255"},
        {"::ffff:1.2.3.4", "1.2.3.4"},     /* v4-mapped prints as IPv4 */
        {"::ffff:0102:0304", "1.2.3.4"},
        {"::", "::"},
        {"::1", "::1"},
        {"2001:db8::1", "2001:db8::1"},
        {"2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
        {"2001:db8:0:1:0:0:0:1", "2001:db8:0:1::1"},      /* longest run */
        {"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
        {"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},    /* first on ties */
        {"2001:db8:1:1:1:1:0:1", "2001:db8:1:1:1:1:0:1"}, /* no :: for one 0 */
        {"fe80::1:2", "fe80::1:2"},
        {"1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0"},
        {"::1.2.3.4", "::102:304"},
        {"64:ff9b::1.2.3.4", "64:ff9b::102:304"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        CHECK_STR_EQ(ipstr(cases[i].in), cases[i].out);

    static const char *const invalid[] = {
        "", "1.2.3", "1.2.3.4.5", "1.2.3.256", "01.2.3.4", "1.2.3.04",
        "1..2.3", ".1.2.3", "1.2.3.", "a.b.c.d", " 1.2.3.4", "1.2.3.4 ",
        "fe80::1%eth0", "::1::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::",
        "12345::", ":1::", "1:", "1:2:3:4:5:6:1.2.3.4:5", "1:2:3:4:5:6:7:1.2.3.4",
        "localhost", "%eth0",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        CHECK_MSG(strcmp(ipstr(invalid[i]), "PARSE-ERROR") == 0,
                  "\"%s\" should not parse", invalid[i]);
}

TEST(string_of_short_forms)
{
    char buf[KS_IP_STRLEN];
    struct ks_ip v4 = ks_ip_v4(10, 0, 0, 1), nil = {{0}, 0};
    ks_ip_string(&v4, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "10.0.0.1");
    ks_ip_string(&nil, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "<nil>");
}

static int contains(const char *cidr, const char *ip)
{
    struct ks_ipnet n;
    struct ks_ip a;
    if (ks_parse_cidr(cidr, &n, NULL, 0) < 0 || ks_ip_parse(ip, &a) < 0)
        return -1;
    return ks_ipnet_contains(&n, &a);
}

TEST(cidr_parse_and_contains)
{
    CHECK_INT_EQ(contains("185.53.178.14/24", "185.53.178.14"), 1);
    CHECK_INT_EQ(contains("185.53.178.14/24", "185.53.178.255"), 1);
    CHECK_INT_EQ(contains("185.53.178.14/24", "185.53.179.1"), 0);
    CHECK_INT_EQ(contains("8.8.8.8/24", "185.53.178.14"), 0);
    CHECK_INT_EQ(contains("0.0.0.0/0", "1.2.3.4"), 1);
    CHECK_INT_EQ(contains("0.0.0.0/0", "::1"), 0);   /* families differ */
    CHECK_INT_EQ(contains("::/0", "1.2.3.4"), 0);
    CHECK_INT_EQ(contains("::/0", "2001:db8::1"), 1);
    CHECK_INT_EQ(contains("fc00::/7", "fd12::1"), 1);
    CHECK_INT_EQ(contains("fc00::/7", "fe80::1"), 0);
    CHECK_INT_EQ(contains("10.0.0.1/32", "10.0.0.1"), 1);
    CHECK_INT_EQ(contains("10.0.0.1/32", "10.0.0.2"), 0);
    CHECK_INT_EQ(contains("2001:db8::/128", "2001:db8::"), 1);
    /* A v4-mapped network is an IPv4 one with the last 32 bits of mask. */
    CHECK_INT_EQ(contains("::ffff:10.0.0.0/104", "10.1.2.3"), 1);
    CHECK_INT_EQ(contains("::ffff:10.0.0.0/104", "11.1.2.3"), 0);
    /* Unless the mask clears the ::ffff prefix: then it's plain IPv6. */
    CHECK_INT_EQ(contains("::ffff:10.0.0.0/64", "99.1.2.3"), 0);
    CHECK_INT_EQ(contains("::ffff:10.0.0.0/64", "::1"), 1);

    struct ks_ipnet n;
    struct ks_ip v4 = ks_ip_v4(192, 168, 1, 7);
    CHECK(ks_parse_cidr("192.168.0.0/16", &n, NULL, 0) == 0);
    CHECK_INT_EQ(n.len, 4);
    CHECK(ks_ipnet_contains(&n, &v4));
    CHECK(ks_parse_cidr("2001:db8::/32", &n, NULL, 0) == 0);
    CHECK_INT_EQ(n.len, 16);
    CHECK(!ks_ipnet_contains(&n, &v4));
}

TEST(cidr_errors)
{
    static const char *const invalid[] = {
        "", "1.2.3.4", "::1", "1.2.3.4/", "1.2.3.4/33", "::/129", "1.2.3.4/-1",
        "1.2.3.4/+8", "1.2.3.4/8 ", "1.2.3.4/0x8", "1.2.3/8", "fe80::%eth0/64",
        "/8", "1.2.3.4/99999999999",
    };
    char err[128];
    struct ks_ipnet n;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CHECK_MSG(ks_parse_cidr(invalid[i], &n, err, sizeof(err)) == -1,
                  "\"%s\" should not parse", invalid[i]);
        char want[128];
        snprintf(want, sizeof(want), "invalid CIDR address: %s", invalid[i]);
        CHECK_STR_EQ(err, want);
    }
    /* Leading zeros in the prefix length are fine for Go's dtoi. */
    CHECK(ks_parse_cidr("10.0.0.0/08", &n, err, sizeof(err)) == 0);
}

TEST(to4)
{
    uint8_t b[4];
    struct ks_ip ip;
    CHECK(ks_ip_parse("::ffff:1.2.3.4", &ip) == 0);
    CHECK(ks_ip_to4(&ip, b) && b[0] == 1 && b[3] == 4);
    CHECK(ks_ip_parse("::1", &ip) == 0);
    CHECK(!ks_ip_to4(&ip, b));
}

int main(void)
{
    RUN(parse_ip_and_string);
    RUN(string_of_short_forms);
    RUN(cidr_parse_and_contains);
    RUN(cidr_errors);
    RUN(to4);
    return harness_report();
}
