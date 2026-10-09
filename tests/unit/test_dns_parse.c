/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * DNS message decoding (daemon/dns/parse.c), with gopacket v1.1.19's
 * behavior as the reference. Messages are copied to buffers of exactly
 * their size, so ASan catches any read past the end.
 */
#include "daemon/dns/parse.h"

#include <stdio.h>
#include <stdlib.h>

#include "tests/harness.h"
#include "tests/unit/dns_build.h"

static struct msg m;
static struct ks_dns_scratch scratch;

/* What the visitor saw. */
static struct seen {
    int nq, na;
    char q[4][256];
    char an[4][256], cname[4][256];
    bool an_nil[4], cname_nil[4];
    uint16_t type[4];
    size_t data_len[4];
} seen;

static void on_q(const struct ks_dns_question *q, void *ud)
{
    (void)ud;
    if (seen.nq < 4)
        snprintf(seen.q[seen.nq], sizeof(seen.q[0]), "%s", q->name.s);
    seen.nq++;
}

static void on_a(const struct ks_dns_rr *rr, void *ud)
{
    (void)ud;
    int i = seen.na++;
    if (i >= 4)
        return;
    snprintf(seen.an[i], sizeof(seen.an[0]), "%s", rr->name.s);
    snprintf(seen.cname[i], sizeof(seen.cname[0]), "%s", rr->cname.s);
    seen.an_nil[i] = rr->name.nil;
    seen.cname_nil[i] = rr->cname.nil;
    seen.type[i] = rr->type;
    seen.data_len[i] = rr->data_len;
}

static const struct ks_dns_visitor visitor = {on_q, on_a, NULL};

/* Decodes data[0..len) from an exact-size copy, with capacity `cap`
 * (extra bytes are zeros). */
static int decode_cap(const uint8_t *data, size_t len, size_t cap)
{
    memset(&seen, 0, sizeof(seen));
    uint8_t *copy = calloc(1, cap ? cap : 1);
    if (copy == NULL)
        abort();
    memcpy(copy, data, len);
    int r = ks_dns_decode(copy, len, cap, NULL, &visitor, &scratch);
    free(copy);
    return r;
}

static int decode(const struct msg *mm)
{
    return decode_cap(mm->b, mm->len, mm->len);
}

TEST(decodes_a_response)
{
    sample_response(&m);
    struct ks_dns_header h;
    CHECK_INT_EQ(ks_dns_decode(m.b, m.len, m.len, &h, NULL, NULL), 0);
    CHECK_INT_EQ(h.id, 0x1234);
    CHECK(h.qr);
    CHECK_INT_EQ(h.qdcount, 1);
    CHECK_INT_EQ(h.ancount, 2);

    CHECK_INT_EQ(decode(&m), 0);
    CHECK_INT_EQ(seen.nq, 1);
    CHECK_STR_EQ(seen.q[0], "www.example.com");
    CHECK_INT_EQ(seen.na, 2);
    CHECK_STR_EQ(seen.an[0], "www.example.com");
    CHECK_INT_EQ(seen.type[0], KS_DNS_TYPE_CNAME);
    CHECK_STR_EQ(seen.cname[0], "cdn.example.net");
    CHECK(!seen.cname_nil[0]);
    CHECK_STR_EQ(seen.an[1], "cdn.example.net");
    CHECK_INT_EQ(seen.type[1], KS_DNS_TYPE_A);
    CHECK_INT_EQ(seen.data_len[1], 4);
    CHECK(seen.cname_nil[1]); /* not a CNAME: nil */
}

TEST(compression_pointers)
{
    /* Answer names pointing at the question, and a name with labels then
     * a pointer. */
    header(&m, 0x8180, 1, 2, 0, 0);
    question(&m, "example.com", 1); /* name at offset 12 */
    ptr(&m, 12);
    rr_head(&m, 1, 4);
    put32(&m, 0x01020304);
    put8(&m, 3);
    put_bytes(&m, "www", 3);
    ptr(&m, 12);
    rr_head(&m, 1, 4);
    put32(&m, 0x01020305);
    CHECK_INT_EQ(decode(&m), 0);
    CHECK_STR_EQ(seen.an[0], "example.com");
    CHECK_STR_EQ(seen.an[1], "www.example.com");
}

TEST(nil_and_empty_names)
{
    /* Root name: nil. A pointer to the root: empty, but not nil. */
    header(&m, 0x8180, 1, 2, 0, 0);
    question(&m, "", 1); /* offset 12: a single 0 */
    name(&m, "");
    rr_head(&m, 1, 4);
    put32(&m, 1);
    ptr(&m, 12);
    rr_head(&m, 1, 4);
    put32(&m, 2);
    CHECK_INT_EQ(decode(&m), 0);
    CHECK(seen.an_nil[0]);
    CHECK(!seen.an_nil[1]);
    CHECK_STR_EQ(seen.an[1], "");
}

TEST(pointer_loops_are_rejected)
{
    /* A name that points to itself. */
    header(&m, 0x8180, 1, 0, 0, 0);
    ptr(&m, 12);
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode(&m), -1);

    /* Two names pointing at each other, with labels in between. */
    header(&m, 0x8180, 1, 0, 0, 0);
    put8(&m, 1);
    put8(&m, 'a');
    ptr(&m, 16); /* 12: "a" -> 16 */
    put8(&m, 1);
    put8(&m, 'b');
    ptr(&m, 12); /* 16: "b" -> 12 */
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode(&m), -1);
}

TEST(recursion_limit_is_gopackets)
{
    /* A question whose name is a chain of k pointers ending at "x": the
     * label is read at level k + 1, and gopacket allows up to 255. */
    for (int k = 252; k <= 256; k++) {
        header(&m, 0x8180, 1, 0, 0, 0);
        size_t x_at = 18 + 2 * (size_t)(k - 1);
        ptr(&m, k >= 2 ? 18 : (unsigned)x_at); /* offset 12 */
        put16(&m, 1);
        put16(&m, 1);
        for (int i = 0; i < k - 1; i++) /* offsets 18, 20, ... */
            ptr(&m, i == k - 2 ? (unsigned)x_at : (unsigned)(18 + 2 * (i + 1)));
        name(&m, "x");
        int r = decode(&m);
        if (k <= 254) {
            CHECK_MSG(r == 0, "%d pointers rejected", k);
            CHECK_STR_EQ(seen.q[0], "x");
        } else {
            CHECK_MSG(r == -1, "%d pointers accepted", k);
        }
    }
}

TEST(truncated_messages_are_rejected)
{
    sample_response(&m);
    for (size_t len = 0; len < m.len; len++)
        CHECK_MSG(decode_cap(m.b, len, len) == -1, "prefix of %zu bytes accepted", len);
}

TEST(invalid_sizes_are_rejected)
{
    /* rdlength past the end */
    sample_response(&m);
    m.b[m.len - 5] = 5;
    CHECK_INT_EQ(decode(&m), -1);

    /* label length past the end */
    header(&m, 0, 1, 0, 0, 0);
    put8(&m, 40);
    put_bytes(&m, "abc", 3);
    CHECK_INT_EQ(decode(&m), -1);

    /* more than 255 bytes of labels in one name */
    header(&m, 0, 1, 0, 0, 0);
    for (int i = 0; i < 5; i++) {
        put8(&m, 60);
        for (int j = 0; j < 60; j++)
            put8(&m, 'a');
    }
    put8(&m, 0);
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode(&m), -1);

    /* exactly 255 is fine: four 62-byte labels + 3 bytes + lengths */
    header(&m, 0, 1, 0, 0, 0);
    for (int i = 0; i < 4; i++) {
        put8(&m, 62);
        for (int j = 0; j < 62; j++)
            put8(&m, 'a');
    }
    put8(&m, 2);
    put_bytes(&m, "zz", 2);
    put8(&m, 0);
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode(&m), 0);

    /* label types 0x40 and 0x80 */
    header(&m, 0, 1, 0, 0, 0);
    put8(&m, 0x41);
    put8(&m, 0);
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode(&m), -1);
    m.b[12] = 0x81;
    CHECK_INT_EQ(decode(&m), -1);

    /* pointer past the end, and pointer cut in half */
    header(&m, 0, 1, 0, 0, 0);
    ptr(&m, 200);
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode(&m), -1);
    header(&m, 0, 1, 0, 0, 0);
    put8(&m, 0xc0);
    CHECK_INT_EQ(decode(&m), -1);

    /* short header */
    header(&m, 0, 0, 0, 0, 0);
    CHECK_INT_EQ(decode_cap(m.b, 11, 11), -1);
    CHECK_INT_EQ(decode_cap(m.b, 12, 12), 0);

    /* counts larger than what's there */
    sample_response(&m);
    m.b[7] = 3;
    CHECK_INT_EQ(decode(&m), -1);
    sample_response(&m);
    m.b[11] = 1;
    CHECK_INT_EQ(decode(&m), -1);
}

TEST(question_fields_may_use_the_capacity)
{
    /* gopacket reads a question's type and class with data[a:b], which
     * only panics past the slice's capacity. */
    header(&m, 0, 1, 0, 0, 0);
    name(&m, "example.com");
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode_cap(m.b, m.len - 4, m.len), 0);
    CHECK_STR_EQ(seen.q[0], "example.com");
    CHECK_INT_EQ(decode_cap(m.b, m.len - 4, m.len - 1), -1);
    /* ... but a record's fixed fields can't: its length check fails. */
    header(&m, 0, 0, 1, 0, 0);
    rr_a(&m, "a", 1, 2, 3, 4);
    CHECK_INT_EQ(decode_cap(m.b, m.len - 6, m.len), -1);
}

TEST(rdata_is_validated)
{
    /* A record data of any length is fine: rr.IP = rr.Data. */
    header(&m, 0, 0, 1, 0, 0);
    name(&m, "a");
    rr_head(&m, 1, 0);
    CHECK_INT_EQ(decode(&m), 0);
    CHECK_INT_EQ(seen.data_len[0], 0);

    /* TXT: character strings must fit */
    header(&m, 0, 0, 1, 0, 0);
    name(&m, "a");
    rr_head(&m, 16, 3);
    put8(&m, 2);
    put_bytes(&m, "hi", 2);
    CHECK_INT_EQ(decode(&m), 0);
    m.b[m.len - 3] = 3;
    CHECK_INT_EQ(decode(&m), -1);

    /* CNAME names can't reach past the record */
    header(&m, 0, 0, 1, 0, 1);
    name(&m, "a");
    rr_head(&m, 5, 2);
    ptr(&m, (unsigned)m.len + 2); /* the next record's name */
    name(&m, "x");
    rr_head(&m, 1, 4);
    put32(&m, 1);
    CHECK_INT_EQ(decode(&m), -1);
    /* empty CNAME data: offset == end */
    header(&m, 0, 0, 1, 0, 0);
    name(&m, "a");
    rr_head(&m, 5, 0);
    CHECK_INT_EQ(decode(&m), -1);

    /* SOA too small; MX, SRV, URI too small */
    static const unsigned types[] = {6, 15, 33, 256};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        header(&m, 0, 0, 1, 0, 0);
        name(&m, "a");
        rr_head(&m, types[i], 1);
        put8(&m, 0);
        CHECK_MSG(decode(&m) == -1, "type %u", types[i]);
    }
    /* well-formed SOA */
    header(&m, 0, 0, 1, 0, 0);
    name(&m, "a");
    rr_head(&m, 6, 22);
    put8(&m, 0);
    put8(&m, 0);
    for (int i = 0; i < 20; i++)
        put8(&m, 0);
    CHECK_INT_EQ(decode(&m), 0);

    /* OPT: options must fit; the extended rcode lands in the header */
    header(&m, 0, 0, 0, 0, 1);
    put8(&m, 0);
    put16(&m, 41);
    put16(&m, 4096);
    put32(&m, 0x01000000); /* extended rcode 1 -> 16 */
    put16(&m, 6);
    put16(&m, 10);
    put16(&m, 2);
    put16(&m, 0xabcd);
    struct ks_dns_header h;
    CHECK_INT_EQ(ks_dns_decode(m.b, m.len, m.len, &h, NULL, NULL), 0);
    CHECK_INT_EQ(h.rcode, 16);
    m.b[m.len - 3] = 3; /* option length 3 > 2 */
    CHECK_INT_EQ(decode(&m), -1);

    /* unknown types are opaque */
    header(&m, 0, 0, 1, 0, 0);
    name(&m, "a");
    rr_head(&m, 999, 1);
    put8(&m, 0xff);
    CHECK_INT_EQ(decode(&m), 0);
}

TEST(errors_in_later_sections_drop_everything)
{
    sample_response(&m);
    m.b[9] = 1; /* NSCOUNT 1 with no authority record */
    CHECK_INT_EQ(decode(&m), -1);
    CHECK_INT_EQ(seen.na, 0); /* nothing handed out */
}

TEST(names_may_hold_any_byte)
{
    header(&m, 0, 1, 0, 0, 0);
    put8(&m, 3);
    put_bytes(&m, "a.b", 3);
    put8(&m, 0);
    put16(&m, 1);
    put16(&m, 1);
    CHECK_INT_EQ(decode(&m), 0);
    CHECK_STR_EQ(seen.q[0], "a.b");
}

TEST(work_is_bounded)
{
    /* A long chain of labels and pointers, and many records pointing at
     * its start: Go would walk ~55 MB; we stop at KS_DNS_WORK_MAX. */
    header(&m, 0, 0, 0, 0, 0);
    size_t chain = m.len;
    for (int i = 0; i < 200; i++) {
        put8(&m, 63);
        for (int j = 0; j < 63; j++)
            put8(&m, 'a');
        if (i < 199)
            ptr(&m, (unsigned)m.len + 2);
        else
            put8(&m, 0);
    }
    unsigned n = 0;
    while (m.len + 12 <= 65535) {
        ptr(&m, (unsigned)chain);
        rr_head(&m, 999, 0);
        n++;
    }
    m.b[6] = (uint8_t)(n >> 8);
    m.b[7] = (uint8_t)n;
    CHECK_INT_EQ(decode(&m), -1);

    /* A big but ordinary response decodes. */
    header(&m, 0x8180, 1, 0, 0, 0);
    question(&m, "many.example.com", 1);
    n = 0;
    while (m.len + 16 <= 65535) {
        ptr(&m, 12);
        rr_head(&m, 1, 4);
        put32(&m, n);
        n++;
    }
    m.b[6] = (uint8_t)(n >> 8);
    m.b[7] = (uint8_t)n;
    CHECK_INT_EQ(decode(&m), 0);
    CHECK_INT_EQ(seen.na, (int)n);
}

int main(void)
{
    RUN(decodes_a_response);
    RUN(compression_pointers);
    RUN(nil_and_empty_names);
    RUN(pointer_loops_are_rejected);
    RUN(recursion_limit_is_gopackets);
    RUN(truncated_messages_are_rejected);
    RUN(invalid_sizes_are_rejected);
    RUN(question_fields_may_use_the_capacity);
    RUN(rdata_is_validated);
    RUN(errors_in_later_sections_drop_everything);
    RUN(names_may_hold_any_byte);
    RUN(work_is_bounded);
    return harness_report();
}
