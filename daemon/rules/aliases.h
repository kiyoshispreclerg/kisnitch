/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Network aliases (network_aliases.json): names like "LAN" that "network"
 * operators can use instead of a CIDR. Port of upstream
 * daemon/rule/operator_aliases.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_aliases owns all names and networks.
 */
#ifndef KS_DAEMON_RULES_ALIASES_H
#define KS_DAEMON_RULES_ALIASES_H

#include <stddef.h>

#include "common/netaddr.h"

#define KS_ALIASES_DEFAULT_FILE "/etc/opensnitchd/network_aliases.json"

struct ks_alias {
    char *name;
    struct ks_ipnet *nets;
    size_t nnets;
};

struct ks_aliases {
    struct ks_alias *items;
    size_t len;
};

/* LoadAliases: adds the aliases in `path` (a JSON object of name -> list of
 * CIDRs) to `a`. Invalid CIDRs are skipped, as upstream (so "::1", without a
 * prefix length, is ignored). An alias seen again is replaced. */
int ks_aliases_load(struct ks_aliases *a, const char *path, char *err,
                    size_t errlen);

/* Same, from a JSON document in memory. */
int ks_aliases_parse(struct ks_aliases *a, const char *json, size_t len,
                     char *err, size_t errlen);

const struct ks_alias *ks_aliases_find(const struct ks_aliases *a,
                                       const char *name);

/* GetAliasByIP: the first alias (in file order; upstream iterates a Go map,
 * in random order) with a network containing `ip`, or NULL. */
const char *ks_aliases_by_ip(const struct ks_aliases *a, const char *ip);

void ks_aliases_free(struct ks_aliases *a);

#endif
