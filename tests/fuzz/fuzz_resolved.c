/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for systemd-resolved monitor replies
 * (daemon/dns/resolved.c): varlink JSON decoded into the DNS cache.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "daemon/dns/cache.h"
#include "daemon/dns/resolved.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int init;
    if (!init) {
        ks_log_set_level(KS_LOG_FATAL + 1);
        init = 1;
    }
    char *buf = malloc(size ? size : 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    ks_resolved_handle_reply(buf, size);
    free(buf);
    if (ks_dns_cache_count() > 1000)
        ks_dns_cache_reset();
    return 0;
}
