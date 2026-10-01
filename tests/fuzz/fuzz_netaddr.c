/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for IP and CIDR parsing (rules and blocklists). A parsed
 * address must print and parse back to itself.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/netaddr.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = malloc(size + 1);
    if (s == NULL)
        return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    struct ks_ip ip, back;
    if (ks_ip_parse(s, &ip) == 0) {
        char str[KS_IP_STRLEN];
        ks_ip_string(&ip, str, sizeof(str));
        if (ks_ip_parse(str, &back) != 0 || memcmp(ip.b, back.b, 16) != 0)
            abort();
    }
    struct ks_ipnet net;
    if (ks_parse_cidr(s, &net, NULL, 0) == 0)
        (void)ks_ipnet_contains(&net, &ip);
    free(s);
    return 0;
}
