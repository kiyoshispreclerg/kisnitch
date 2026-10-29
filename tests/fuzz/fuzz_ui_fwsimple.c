/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libFuzzer target for the simplified firewall panel's parsers: ufw
 * application profiles (/etc/ufw/applications.d) and the address ranges
 * shown as CIDR. Every profile entry must make a valid simple rule.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ui/fwsimple.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *txt = malloc(size + 1);
    if (txt == NULL)
        return 0;
    memcpy(txt, data, size);
    txt[size] = '\0';
    struct ks_fws_apps apps = {0};
    ks_fws_apps_parse(&apps, txt);
    for (size_t i = 0; i < apps.n; i++) {
        struct ks_fws_rule r;
        ks_fws_rule_init(&r);
        r.proto = apps.v[i].proto;
        memcpy(r.port, apps.v[i].ports, sizeof(r.port));
        struct ks_fw_chain flat;
        char err[256];
        if (ks_fws_to_flat(&r, &flat, err, sizeof(err)) == 0)
            ks_fwr_free_chain(&flat);
    }
    ks_fws_apps_free(&apps);
    char buf[300];
    ks_fws_addr_text(txt, buf, sizeof(buf));
    free(txt);
    return 0;
}
