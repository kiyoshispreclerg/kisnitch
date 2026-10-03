/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for /proc/net line parsing (tcp/udp style and packet).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"
#include "daemon/netstat.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = malloc(size + 1);
    if (s == NULL)
        return 0;
    memcpy(s, data, size);
    s[size] = '\0';
    ks_log_set_level(KS_LOG_FATAL + 1);

    struct ks_netstat_entry e;
    if (ks_netstat_parse_line("tcp6", s, &e) == 0) {
        char ip[KS_IP_STRLEN];
        ks_ip_string(&e.src_ip, ip, sizeof(ip));
        ks_ip_string(&e.dst_ip, ip, sizeof(ip));
        if (e.src_port > 0xffff || e.dst_port > 0xffff || e.uid < 0 || e.inode < 0)
            abort();
    }
    (void)ks_netstat_parse_packet_line(s, &e);
    free(s);
    return 0;
}
