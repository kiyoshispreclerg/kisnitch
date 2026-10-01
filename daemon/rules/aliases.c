/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of upstream daemon/rule/operator_aliases.go.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "daemon/rules/aliases.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/json_util.h"

#define ALIASES_MAX_SIZE (1024 * 1024)

static void free_alias(struct ks_alias *al)
{
    free(al->name);
    free(al->nets);
    memset(al, 0, sizeof(*al));
}

void ks_aliases_free(struct ks_aliases *a)
{
    for (size_t i = 0; i < a->len; i++)
        free_alias(&a->items[i]);
    free(a->items);
    memset(a, 0, sizeof(*a));
}

const struct ks_alias *ks_aliases_find(const struct ks_aliases *a,
                                       const char *name)
{
    if (a == NULL)
        return NULL;
    for (size_t i = 0; i < a->len; i++)
        if (strcmp(a->items[i].name, name) == 0)
            return &a->items[i];
    return NULL;
}

const char *ks_aliases_by_ip(const struct ks_aliases *a, const char *ip)
{
    struct ks_ip addr;
    if (a == NULL)
        return NULL;
    /* net.ParseIP returns nil on error, which no network contains. */
    if (ks_ip_parse(ip, &addr) < 0)
        return NULL;
    for (size_t i = 0; i < a->len; i++)
        for (size_t j = 0; j < a->items[i].nnets; j++)
            if (ks_ipnet_contains(&a->items[i].nets[j], &addr))
                return a->items[i].name;
    return NULL;
}

/* json.Unmarshal into map[string][]string: everything is checked before
 * anything is added, since upstream returns early on error. */
static int check_shape(const cJSON *root, char *err, size_t errlen)
{
    if (cJSON_IsNull(root))
        return 0;
    if (!cJSON_IsObject(root)) {
        snprintf(err, errlen, "aliases: expected an object");
        return -1;
    }
    const cJSON *item;
    cJSON_ArrayForEach(item, root) {
        if (cJSON_IsNull(item))
            continue;
        if (!cJSON_IsArray(item)) {
            snprintf(err, errlen, "aliases: %s: expected an array of strings",
                     item->string);
            return -1;
        }
        const cJSON *net;
        cJSON_ArrayForEach(net, item) {
            if (!cJSON_IsString(net) && !cJSON_IsNull(net)) {
                snprintf(err, errlen, "aliases: %s: expected an array of strings",
                         item->string);
                return -1;
            }
        }
    }
    return 0;
}

int ks_aliases_parse(struct ks_aliases *a, const char *json, size_t len,
                     char *err, size_t errlen)
{
    char perr[200];
    cJSON *root = ks_json_parse(json, len, perr, sizeof(perr));
    if (root == NULL) {
        snprintf(err, errlen, "%s", perr);
        return -1;
    }
    if (check_shape(root, err, errlen) < 0) {
        cJSON_Delete(root);
        return -1;
    }

    const cJSON *item;
    cJSON_ArrayForEach(item, root) {
        struct ks_alias al = {0};
        size_t n = (size_t)cJSON_GetArraySize(item);
        al.name = strdup(item->string);
        al.nets = n ? calloc(n, sizeof(*al.nets)) : NULL;
        if (al.name == NULL || (n && al.nets == NULL))
            goto oom;

        const cJSON *net;
        cJSON_ArrayForEach(net, item) {
            /* A null element decodes to "", which isn't a valid CIDR. */
            const char *s = cJSON_IsString(net) ? net->valuestring : "";
            if (ks_parse_cidr(s, &al.nets[al.nnets], NULL, 0) == 0)
                al.nnets++;
        }

        /* AliasIPCache[alias] = ipNets: replace an existing alias. */
        struct ks_alias *old = (struct ks_alias *)ks_aliases_find(a, al.name);
        if (old != NULL) {
            free_alias(old);
            *old = al;
            continue;
        }
        struct ks_alias *items = realloc(a->items, (a->len + 1) * sizeof(*items));
        if (items == NULL)
            goto oom;
        a->items = items;
        a->items[a->len++] = al;
        continue;
oom:
        free_alias(&al);
        cJSON_Delete(root);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    cJSON_Delete(root);
    return 0;
}

int ks_aliases_load(struct ks_aliases *a, const char *path, char *err,
                    size_t errlen)
{
    size_t len;
    char *raw = ks_read_file(path, ALIASES_MAX_SIZE, &len, err, errlen);
    if (raw == NULL)
        return -1;
    int ret = ks_aliases_parse(a, raw, len, err, errlen);
    free(raw);
    return ret;
}
