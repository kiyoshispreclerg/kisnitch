/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for DNS decoding (daemon/dns/parse.c): DNS responses
 * reach the daemon, running as root, straight from the network.
 *
 * The first byte picks how many bytes past the message the buffer has
 * (the capacity some gopacket reads go up to); the rest is the message.
 * Both decoding modes run: validation only, and with the visitor.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "daemon/dns/parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static struct ks_dns_scratch scratch;

static void check_name(const struct ks_dns_name *n)
{
    if (n->nil && n->len != 0)
        abort();
    if (n->len >= KS_DNS_NAME_MAX || n->s[n->len] != '\0')
        abort();
}

static void on_q(const struct ks_dns_question *q, void *ud)
{
    (void)ud;
    check_name(&q->name);
}

static void on_a(const struct ks_dns_rr *rr, void *ud)
{
    const uint8_t **bounds = ud;
    check_name(&rr->name);
    check_name(&rr->cname);
    if (rr->type != KS_DNS_TYPE_CNAME && !rr->cname.nil)
        abort();
    if (rr->data < bounds[0] || rr->data + rr->data_len > bounds[1])
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    size_t extra = data[0] % 8;
    size_t len = size - 1;
    /* An exact-size copy, so ASan sees any overread. */
    uint8_t *buf = malloc(len + extra ? len + extra : 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data + 1, len);
    memset(buf + len, 0xaa, extra);

    const uint8_t *bounds[2] = {buf, buf + len};
    struct ks_dns_visitor v = {on_q, on_a, bounds};
    struct ks_dns_header h;
    int r1 = ks_dns_decode(buf, len, len + extra, &h, NULL, NULL);
    int r2 = ks_dns_decode(buf, len, len + extra, NULL, &v, &scratch);
    if (r1 != r2)
        abort();
    free(buf);
    return 0;
}
