/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of gopacket v1.1.19 layers/dns.go: DNS.DecodeFromBytes, decodeName,
 * DNSQuestion.decode, DNSResourceRecord.decode/decodeRData,
 * decodeCharacterStrings and decodeOPTs. Only validation and the fields
 * upstream reads are kept; the error messages are not (nobody sees them).
 *
 * Copyright (C) 2012 Google, Inc. (gopacket, BSD-3-Clause)
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/dns/parse.h"

#include <string.h>

/* maxRecursionLevel */
#define MAX_RECURSION 255

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

struct walk {
    const uint8_t *data;
    size_t len; /* len(data) */
    size_t cap; /* cap(data) */
    size_t work;
};

/* decodeName(data[:len], offset, buffer, 1). The recursion on compression
 * pointers is a loop here: after a pointer, Go only returns. `buf` (may be
 * NULL) receives the name; *end gets the offset after the name as seen
 * from the first level. */
static int decode_name(struct walk *w, size_t len, size_t offset, char *buf,
                       struct ks_dns_name *out, size_t *end)
{
    const uint8_t *data = w->data;
    size_t n = 0; /* bytes appended to the buffer, leading '.' included */
    bool first = true, nil = false;
    size_t off = offset;

    for (int level = 1;; level++) {
        if (level > MAX_RECURSION || off >= len)
            return -1; /* errMaxRecursion, errDNSNameOffsetTooHigh */
        size_t index = off;
        if (data[index] == 0x00) {
            if (first) {
                nil = true;
                *end = index + 1;
            }
            break;
        }
        bool jumped = false;
        while (data[index] != 0x00 && !jumped) {
            switch (data[index] & 0xc0) {
            case 0x00: {
                size_t index2 = index + data[index] + 1;
                if (index2 - off > 255 || index2 > len)
                    return -1; /* errDNSNameTooLong, errDNSNameInvalidIndex */
                size_t l = index2 - index - 1;
                w->work += l + 1;
                /* The second test can't fail (255 levels of at most 255
                 * bytes); it keeps the copy below obviously in bounds. */
                if (w->work > KS_DNS_WORK_MAX || n + l + 1 >= KS_DNS_NAME_MAX)
                    return -1;
                if (buf != NULL) {
                    buf[n] = '.';
                    memcpy(buf + n + 1, data + index + 1, l);
                }
                n += l + 1;
                index = index2;
                break;
            }
            case 0xc0: {
                if (index + 2 > len)
                    return -1; /* errDNSPointerOffsetTooHigh */
                size_t p = be16(data + index) & 0x3fff;
                if (p > len)
                    return -1;
                if (++w->work > KS_DNS_WORK_MAX)
                    return -1;
                if (first)
                    *end = index + 2; /* index++; ... return index + 1 */
                first = false;
                off = p;
                jumped = true;
                continue; /* the next level starts with the checks above */
            }
            default: /* 0x40 (RFC 2673) and 0x80: unsupported */
                return -1;
            }
            if (index >= len)
                return -1; /* errDNSIndexOutOfRange */
        }
        if (!jumped) {
            if (first)
                *end = index + 1;
            break;
        }
    }

    if (out != NULL) {
        out->nil = nil;
        if (buf != NULL)
            buf[n] = '\0';
        /* (*buffer)[start:] when nothing was appended, else [start+1:] */
        out->s = buf == NULL ? "" : n == 0 ? buf : buf + 1;
        out->len = n == 0 ? 0 : n - 1;
    }
    return 0;
}

/* DNSQuestion.decode */
static int decode_question(struct walk *w, size_t *offset, char *buf, struct ks_dns_question *q)
{
    size_t endq;
    if (decode_name(w, w->len, *offset, buf, q ? &q->name : NULL, &endq) < 0)
        return -1;
    /* data[endq:endq+4] panics only past the slice's capacity. */
    if (endq + 4 > w->cap)
        return -1;
    if (q != NULL) {
        q->type = be16(w->data + endq);
        q->klass = be16(w->data + endq + 2);
    }
    *offset = endq + 4;
    return 0;
}

/* decodeCharacterStrings */
static int decode_character_strings(const uint8_t *data, size_t len)
{
    for (size_t index = 0, index2; index != len; index = index2) {
        index2 = index + 1 + data[index];
        if (index2 > len)
            return -1; /* errCharStringMissData */
    }
    return 0;
}

/* decodeOPTs(data[:end], offset) */
static int decode_opts(const uint8_t *data, size_t end, size_t offset)
{
    if (offset == end)
        return 0;
    if (offset + 4 > end)
        return -1;
    for (size_t i = offset; i < end;) {
        if (end < i + 4)
            return -1;
        size_t l = be16(data + i + 2);
        if (i + 4 + l > end)
            return -1;
        i += l + 4;
    }
    return 0;
}

/* DNSResourceRecord.decodeRData(data[:end], offset, buffer) */
static int decode_rdata(struct walk *w, size_t end, size_t offset, struct ks_dns_rr *rr,
                        char *cname_buf)
{
    size_t endq;
    switch (rr->type) {
    case KS_DNS_TYPE_A:
    case KS_DNS_TYPE_AAAA:
        return 0; /* rr.IP = rr.Data */
    case KS_DNS_TYPE_TXT:
    case KS_DNS_TYPE_HINFO:
        return decode_character_strings(rr->data, rr->data_len);
    case KS_DNS_TYPE_CNAME:
        return decode_name(w, end, offset, cname_buf, &rr->cname, &endq);
    case KS_DNS_TYPE_NS:
    case KS_DNS_TYPE_PTR:
        return decode_name(w, end, offset, NULL, NULL, &endq);
    case KS_DNS_TYPE_SOA:
        if (decode_name(w, end, offset, NULL, NULL, &endq) < 0 ||
            decode_name(w, end, endq, NULL, NULL, &endq) < 0)
            return -1;
        return end < endq + 20 ? -1 : 0; /* "SOA too small" */
    case KS_DNS_TYPE_MX:
        if (end < offset + 2)
            return -1;
        return decode_name(w, end, offset + 2, NULL, NULL, &endq);
    case KS_DNS_TYPE_URI:
        return rr->data_len < 4 ? -1 : 0;
    case KS_DNS_TYPE_SRV:
        if (end < offset + 6)
            return -1;
        return decode_name(w, end, offset + 6, NULL, NULL, &endq);
    case KS_DNS_TYPE_OPT:
        return decode_opts(w->data, end, offset);
    default:
        return 0;
    }
}

/* DNSResourceRecord.decode. `name_buf` and `cname_buf` may be NULL. */
static int decode_rr(struct walk *w, size_t *offset, char *name_buf, char *cname_buf,
                     struct ks_dns_rr *rr)
{
    size_t endq;
    memset(rr, 0, sizeof(*rr));
    rr->cname.nil = true;
    rr->cname.s = "";
    if (decode_name(w, w->len, *offset, name_buf, &rr->name, &endq) < 0)
        return -1;
    /* Reading the 10 fixed bytes past the capacity panics; past the length
     * the record length check below fails anyway. */
    if (endq + 10 > w->len)
        return -1;
    const uint8_t *d = w->data;
    rr->type = be16(d + endq);
    rr->klass = be16(d + endq + 2);
    rr->ttl = be32(d + endq + 4);
    size_t end = endq + 10 + be16(d + endq + 8);
    if (end > w->len)
        return -1; /* errDecodeRecordLength */
    rr->data = d + endq + 10;
    rr->data_len = end - (endq + 10);
    if (decode_rdata(w, end, endq + 10, rr, cname_buf) < 0)
        return -1;
    *offset = end;
    return 0;
}

static int walk_message(struct walk *w, struct ks_dns_header *hdr, const struct ks_dns_visitor *v,
                        struct ks_dns_scratch *s)
{
    const uint8_t *d = w->data;
    if (w->len < 12)
        return -1; /* errDNSPacketTooShort */
    hdr->id = be16(d);
    hdr->qr = (d[2] & 0x80) != 0;
    hdr->opcode = (d[2] >> 3) & 0x0f;
    hdr->rcode = d[3] & 0x0f;
    hdr->qdcount = be16(d + 4);
    hdr->ancount = be16(d + 6);
    hdr->nscount = be16(d + 8);
    hdr->arcount = be16(d + 10);

    size_t offset = 12;
    for (unsigned i = 0; i < hdr->qdcount; i++) {
        struct ks_dns_question q;
        bool emit = v != NULL && v->question != NULL;
        if (decode_question(w, &offset, emit ? s->name : NULL, emit ? &q : NULL) < 0)
            return -1;
        if (emit)
            v->question(&q, v->ud);
    }
    for (unsigned i = 0; i < hdr->ancount; i++) {
        struct ks_dns_rr rr;
        bool emit = v != NULL && v->answer != NULL;
        if (decode_rr(w, &offset, emit ? s->name : NULL, emit ? s->cname : NULL, &rr) < 0)
            return -1;
        if (emit)
            v->answer(&rr, v->ud);
    }
    for (unsigned i = 0; i < hdr->nscount; i++) {
        struct ks_dns_rr rr;
        if (decode_rr(w, &offset, NULL, NULL, &rr) < 0)
            return -1;
    }
    for (unsigned i = 0; i < hdr->arcount; i++) {
        struct ks_dns_rr rr;
        if (decode_rr(w, &offset, NULL, NULL, &rr) < 0)
            return -1;
        if (rr.type == KS_DNS_TYPE_OPT)
            hdr->rcode = (uint8_t)(hdr->rcode | ((rr.ttl >> 20) & 0xf0));
    }
    /* The section counts always match here: every loop above either
     * decoded all its entries or returned. */
    return 0;
}

int ks_dns_decode(const uint8_t *data, size_t len, size_t cap, struct ks_dns_header *hdr,
                  const struct ks_dns_visitor *v, struct ks_dns_scratch *scratch)
{
    struct ks_dns_header h;
    struct walk w = {.data = data, .len = len, .cap = cap < len ? len : cap};

    /* First validate the whole message, as gopacket only adds the layer
     * when everything decodes; then hand the parts out. */
    if (walk_message(&w, &h, NULL, NULL) < 0)
        return -1;
    if (v != NULL && (v->question != NULL || v->answer != NULL)) {
        w.work = 0;
        if (walk_message(&w, &h, v, scratch) < 0)
            return -1; /* can't happen: same input, same walk */
    }
    if (hdr != NULL)
        *hdr = h;
    return 0;
}
