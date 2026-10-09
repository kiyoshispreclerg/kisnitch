/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * DNS message decoding. Port of gopacket v1.1.19 layers/dns.go
 * (DNS.DecodeFromBytes and its helpers), which upstream uses through
 * packet.Layer(layers.LayerTypeDNS) in daemon/dns/track.go and parse.go.
 *
 * gopacket only adds the DNS layer when the whole message decodes: every
 * question and every answer, authority and additional record, including
 * the record data of the types it knows. A message is either accepted as a
 * whole or rejected, and only an accepted one is handed to the visitor.
 *
 * Out-of-range reads that make Go panic (and gopacket recover, without
 * adding the layer) are errors here. As in Go, the fixed-size fields after
 * a question's name may be read past the DNS payload, up to the end of the
 * packet buffer (the slice's capacity): `cap` says how far that is.
 *
 * Copyright (C) 2012 Google, Inc. (gopacket, BSD-3-Clause)
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: names handed to the visitor live in the caller's struct
 * ks_dns_scratch and are only valid during the callback. Nothing is
 * allocated.
 */
#ifndef KS_DAEMON_DNS_PARSE_H
#define KS_DAEMON_DNS_PARSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* DNSType values upstream looks at. */
#define KS_DNS_TYPE_A 1
#define KS_DNS_TYPE_NS 2
#define KS_DNS_TYPE_CNAME 5
#define KS_DNS_TYPE_SOA 6
#define KS_DNS_TYPE_PTR 12
#define KS_DNS_TYPE_HINFO 13
#define KS_DNS_TYPE_MX 15
#define KS_DNS_TYPE_TXT 16
#define KS_DNS_TYPE_AAAA 28
#define KS_DNS_TYPE_SRV 33
#define KS_DNS_TYPE_OPT 41
#define KS_DNS_TYPE_URI 256

/* Longest name decodeName() can assemble (255 levels of compression
 * pointers, at most 255 bytes of labels each), plus a NUL. */
#define KS_DNS_NAME_MAX 65536

/* A decoded name ([]byte in gopacket). Go tells nil (a name that is just
 * the root label) from empty (a pointer to the root label); upstream checks
 * `!= nil`, so the difference matters. `s` is NUL-terminated, but labels may
 * contain any byte, NUL included: use `len`. */
struct ks_dns_name {
    const char *s;
    size_t len;
    bool nil;
};

struct ks_dns_question {
    struct ks_dns_name name; /* Name */
    uint16_t type, klass;    /* Type, Class */
};

struct ks_dns_rr {
    struct ks_dns_name name; /* Name */
    uint16_t type, klass;    /* Type, Class */
    uint32_t ttl;            /* TTL */
    const uint8_t *data;     /* Data (also IP for A and AAAA, any length) */
    size_t data_len;
    /* CNAME: decoded for type CNAME only; nil otherwise. */
    struct ks_dns_name cname;
};

struct ks_dns_header {
    uint16_t id;
    bool qr;
    uint8_t opcode;
    uint8_t rcode; /* ResponseCode, including the OPT extended bits */
    uint16_t qdcount, ancount, nscount, arcount;
};

/* Called for each question and each record of the answer section, in
 * order, once the whole message is known to decode. Either may be NULL. */
struct ks_dns_visitor {
    void (*question)(const struct ks_dns_question *q, void *ud);
    void (*answer)(const struct ks_dns_rr *rr, void *ud);
    void *ud;
};

/* Room for the names given to the visitor. Big: don't put it on the stack
 * of a deep call chain. */
struct ks_dns_scratch {
    char name[KS_DNS_NAME_MAX];
    char cname[KS_DNS_NAME_MAX];
};

/* Upper bound on the bytes the name decoder may walk in one message
 * (see docs/UPSTREAM.md, divergences). */
#define KS_DNS_WORK_MAX ((size_t)1 << 22)

/* DNS.DecodeFromBytes on data[0..len); cap >= len is how many bytes the
 * buffer really has from `data` on. Returns 0 if gopacket would add the DNS
 * layer, filling `hdr` (may be NULL) and calling the visitor (may be NULL;
 * then `scratch` may be NULL too); -1 otherwise. */
int ks_dns_decode(const uint8_t *data, size_t len, size_t cap, struct ks_dns_header *hdr,
                  const struct ks_dns_visitor *v, struct ks_dns_scratch *scratch);

#endif
