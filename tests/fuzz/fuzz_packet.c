/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for packet decoding (daemon/conn.c): the bytes nfqueue
 * hands us come from local programs and, for DNS responses, from the
 * network. Decoded packets also go through the DNS tracking of
 * daemon/dns/cache.c, as in onPacket().
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "daemon/conn.h"
#include "daemon/dns/cache.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* A copy of exactly `size` bytes, so ASan sees any overread. */
    uint8_t *buf = malloc(size ? size : 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);

    struct ks_packet p;
    ks_packet_decode(buf, size, &p);
    const char *proto = ks_packet_protocol(&p);
    if ((proto == NULL) != (p.l4 == KS_L4_NONE))
        abort();
    if (p.sport > 0xffff || p.dport > 0xffff)
        abort();
    if (p.src.len != 0 && p.src.len != 4 && p.src.len != 16)
        abort();
    if (p.udp_payload != NULL &&
        (p.udp_payload < buf || p.udp_payload + p.udp_payload_len > buf + size ||
         p.udp_payload + p.udp_payload_cap != buf + size))
        abort();

    static int init;
    if (!init) {
        ks_log_set_level(KS_LOG_FATAL + 1);
        init = 1;
    }
    ks_dns_track_answers(&p);
    free(ks_dns_query_domain(&p));
    if (ks_dns_cache_count() > 1000)
        ks_dns_cache_reset();
    free(buf);
    return 0;
}
