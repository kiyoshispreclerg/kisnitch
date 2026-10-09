/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Resolved names (daemon/dns/cache.c): dns.Track, Host, HostOr,
 * TrackAnswers and GetQuestions, on packets built by hand.
 */
#include "daemon/dns/cache.h"

#include <stdio.h>
#include <stdlib.h>

#include "common/log.h"
#include "tests/harness.h"
#include "tests/unit/dns_build.h"

static struct msg m;

static char *host_or(const char *ip, const char *or)
{
    struct ks_ip a;
    if (ks_ip_parse(ip, &a) < 0)
        abort();
    return ks_dns_host_or(&a, or);
}

#define CHECK_HOST_OR(ip, or, want)                                          \
    do {                                                                     \
        char *got_ = host_or(ip, or);                                        \
        CHECK(got_ != NULL);                                                 \
        if (got_ != NULL)                                                    \
            CHECK_STR_EQ(got_, want);                                        \
        free(got_);                                                          \
    } while (0)

static bool track_packet(const struct msg *mm, unsigned sport, unsigned dport)
{
    size_t len;
    uint8_t *p = udp_packet(mm, sport, dport, &len);
    struct ks_packet pkt;
    ks_packet_decode(p, len, &pkt);
    bool r = ks_dns_track_answers(&pkt);
    free(p);
    return r;
}

static char *query_domain(const struct msg *mm, unsigned sport, unsigned dport)
{
    size_t len;
    uint8_t *p = udp_packet(mm, sport, dport, &len);
    struct ks_packet pkt;
    ks_packet_decode(p, len, &pkt);
    char *r = ks_dns_query_domain(&pkt);
    free(p);
    return r;
}

TEST(track_and_host)
{
    ks_dns_cache_reset();
    ks_dns_track("1.2.3.4", "example.com");
    CHECK_STR_EQ(ks_dns_host("1.2.3.4"), "example.com");
    CHECK(ks_dns_host("1.2.3.5") == NULL);
    /* a later answer replaces the name */
    ks_dns_track("1.2.3.4", "example.org");
    CHECK_STR_EQ(ks_dns_host("1.2.3.4"), "example.org");
    CHECK_INT_EQ(ks_dns_cache_count(), 1);

    /* skipped: loopback answers and self references */
    ks_dns_track("127.0.0.53", "localhost.example");
    ks_dns_track("::1", "localhost6.example");
    ks_dns_track("same.example", "same.example");
    CHECK_INT_EQ(ks_dns_cache_count(), 1);
    /* only "127." as a prefix */
    ks_dns_track("127", "x.example");
    ks_dns_track("10.127.0.1", "y.example");
    CHECK_INT_EQ(ks_dns_cache_count(), 3);
}

TEST(host_or_follows_cnames)
{
    ks_dns_cache_reset();
    CHECK_HOST_OR("93.184.216.34", "", "");
    CHECK_HOST_OR("93.184.216.34", "fallback", "fallback");

    ks_dns_track("93.184.216.34", "cdn.example.net");
    ks_dns_track("cdn.example.net", "www.example.com");
    CHECK_HOST_OR("93.184.216.34", "", "www.example.com");

    /* IPv6 keys are IP.String() */
    ks_dns_track("2001:db8::1", "v6.example.com");
    CHECK_HOST_OR("2001:0db8:0:0::1", "", "v6.example.com");

    /* loops end: ip -> a -> b -> a. Go returns "a" (it sees b, then a,
     * then b again). */
    ks_dns_track("10.0.0.1", "a");
    ks_dns_track("a", "b");
    ks_dns_track("b", "a");
    CHECK_HOST_OR("10.0.0.1", "", "a");
}

TEST(cache_is_bounded)
{
    ks_dns_cache_reset();
    char ip[32], host[32];
    for (int i = 0; i < KS_DNS_CACHE_MAX; i++) {
        snprintf(ip, sizeof(ip), "10.%d.%d.%d", i >> 16, (i >> 8) & 255, i & 255);
        snprintf(host, sizeof(host), "h%d.example", i);
        ks_dns_track(ip, host);
    }
    CHECK_INT_EQ(ks_dns_cache_count(), KS_DNS_CACHE_MAX);
    /* using the oldest entry keeps it; the next oldest goes */
    CHECK_STR_EQ(ks_dns_host("10.0.0.0"), "h0.example");
    ks_dns_track("192.0.2.1", "new.example");
    CHECK_INT_EQ(ks_dns_cache_count(), KS_DNS_CACHE_MAX);
    CHECK(ks_dns_host("10.0.0.0") != NULL);
    CHECK(ks_dns_host("10.0.0.1") == NULL);
    CHECK_STR_EQ(ks_dns_host("192.0.2.1"), "new.example");
    ks_dns_cache_reset();
    CHECK_INT_EQ(ks_dns_cache_count(), 0);
}

TEST(track_answers)
{
    ks_dns_cache_reset();
    sample_response(&m);
    CHECK(track_packet(&m, 53, 40000));
    CHECK_STR_EQ(ks_dns_host("93.184.216.34"), "cdn.example.net");
    CHECK_STR_EQ(ks_dns_host("cdn.example.net"), "www.example.com");
    CHECK_HOST_OR("93.184.216.34", "", "www.example.com");

    /* AAAA */
    header(&m, 0x8180, 0, 1, 0, 0);
    name(&m, "v6.example.com");
    rr_head(&m, 28, 16);
    static const uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 7};
    put_bytes(&m, v6, 16);
    CHECK(track_packet(&m, 53, 40000));
    CHECK_STR_EQ(ks_dns_host("2001:db8::7"), "v6.example.com");

    /* An A record with 3 bytes of data: net.IP.String() gives "?..." */
    header(&m, 0x8180, 0, 1, 0, 0);
    name(&m, "odd.example.com");
    rr_head(&m, 1, 3);
    put_bytes(&m, "\x0a\x0b\x0c", 3);
    CHECK(track_packet(&m, 53, 40000));
    CHECK_STR_EQ(ks_dns_host("?0a0b0c"), "odd.example.com");

    /* An answer with a root (nil) name is skipped, the packet still
     * counts as DNS. */
    ks_dns_cache_reset();
    header(&m, 0x8180, 0, 1, 0, 0);
    rr_a(&m, "", 1, 2, 3, 4);
    CHECK(track_packet(&m, 53, 40000));
    CHECK_INT_EQ(ks_dns_cache_count(), 0);

    /* Names with NUL bytes are left out. */
    header(&m, 0x8180, 0, 1, 0, 0);
    put8(&m, 3);
    put_bytes(&m, "a\0b", 3);
    put8(&m, 0);
    rr_head(&m, 1, 4);
    put32(&m, 0x01020304);
    CHECK(track_packet(&m, 53, 40000));
    CHECK_INT_EQ(ks_dns_cache_count(), 0);
}

TEST(which_packets_are_dns)
{
    ks_dns_cache_reset();
    sample_response(&m);
    /* source port 53 required */
    CHECK(!track_packet(&m, 5353, 53));
    /* destination ports with a layer of their own win (123 is NTP) */
    CHECK(!track_packet(&m, 53, 123));
    CHECK(!track_packet(&m, 53, 67));
    /* other destination ports fall back to the source port */
    CHECK(track_packet(&m, 53, 5353));
    CHECK(track_packet(&m, 53, 53));
    /* not DNS */
    m.len = 11;
    CHECK(!track_packet(&m, 53, 40000));
    m.len = 0; /* empty payload: no next layer */
    CHECK(!track_packet(&m, 53, 40000));

    /* TCP from port 53 never decodes as DNS */
    sample_response(&m);
    size_t len;
    uint8_t *p = udp_packet(&m, 53, 40000, &len);
    p[9] = 6;
    p[20 + 12] = 0x50;
    struct ks_packet pkt;
    ks_packet_decode(p, len, &pkt);
    CHECK(!ks_dns_track_answers(&pkt));
    CHECK(ks_dns_query_domain(&pkt) == NULL);
    free(p);
}

TEST(query_domain_is_the_last_question)
{
    header(&m, 0x0100, 2, 0, 0, 0);
    question(&m, "first.example.com", 1);
    question(&m, "last.example.com", 28);
    char *d = query_domain(&m, 40000, 53);
    CHECK(d != NULL);
    if (d != NULL)
        CHECK_STR_EQ(d, "last.example.com");
    free(d);

    header(&m, 0x0100, 0, 0, 0, 0);
    CHECK(query_domain(&m, 40000, 53) == NULL);
    m.len = 5;
    CHECK(query_domain(&m, 40000, 53) == NULL);
}

TEST(ip_string)
{
    static const struct {
        const char *b;
        size_t len;
        const char *want;
    } cases[] = {
        {"", 0, "<nil>"},
        {"\x01\x02\x03\x04", 4, "1.2.3.4"},
        {"\0\0\0\0\0\0\0\0\0\0\xff\xff\x01\x02\x03\x04", 16, "1.2.3.4"},
        {"\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01", 16, "2001:db8::1"},
        {"\xab", 1, "?ab"},
        {"\x01\x02\x03\x04\x05", 5, "?0102030405"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *s = ks_dns_ip_string((const uint8_t *)cases[i].b, cases[i].len);
        CHECK(s != NULL);
        if (s != NULL)
            CHECK_STR_EQ(s, cases[i].want);
        free(s);
    }
}

int main(void)
{
    ks_log_set_level(KS_LOG_FATAL + 1);
    RUN(track_and_host);
    RUN(host_or_follows_cnames);
    RUN(cache_is_bounded);
    RUN(track_answers);
    RUN(which_packets_are_dns);
    RUN(query_domain_is_the_last_question);
    RUN(ip_string);
    ks_dns_cache_reset();
    return harness_report();
}
