/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of the loading part of upstream
 * ui/opensnitch/dialogs/processdetails.py. See procinfo.h.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/procinfo.h"

#include <glib.h>
#include <math.h>
#include <string.h>

#include "common/json_util.h"

bool ks_procinfo_parse(struct ks_procinfo *p, const char *json)
{
    char err[96];
    p->j = ks_json_parse(json, strlen(json), err, sizeof(err));
    if (!cJSON_IsObject(p->j) || !cJSON_IsString(cJSON_GetObjectItemCaseSensitive(p->j, "Path")) ||
        !cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(p->j, "Args"))) {
        cJSON_Delete(p->j);
        p->j = NULL;
        return false;
    }
    return true;
}

void ks_procinfo_free(struct ks_procinfo *p)
{
    cJSON_Delete(p->j);
    p->j = NULL;
}

static const cJSON *get(const struct ks_procinfo *p, const char *k)
{
    return cJSON_GetObjectItemCaseSensitive(p->j, k);
}

static const char *str(const cJSON *o, const char *k)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(v) ? v->valuestring : "";
}

static double num(const cJSON *o, const char *k)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsNumber(v) ? v->valuedouble : 0;
}

char *ks_procinfo_path(const struct ks_procinfo *p)
{
    const char *path = str(p->j, "Path");
    const cJSON *a;
    cJSON_ArrayForEach(a, get(p, "Args"))
    {
        if (cJSON_IsString(a) && strcmp(a->valuestring, path) == 0)
            return NULL;
    }
    char *e = g_markup_escape_text(path, -1);
    char *r = g_strdup_printf("(%s)", e);
    g_free(e);
    return r;
}

char *ks_procinfo_args(const struct ks_procinfo *p)
{
    GString *g = g_string_new(NULL);
    const cJSON *a;
    cJSON_ArrayForEach(a, get(p, "Args"))
    {
        if (g->len > 0 || a != get(p, "Args")->child)
            g_string_append_c(g, ' ');
        g_string_append(g, cJSON_IsString(a) ? a->valuestring : "");
    }
    return g_string_free(g, FALSE);
}

char *ks_procinfo_cwd(const struct ks_procinfo *p)
{
    char *e = g_markup_escape_text(str(p->j, "CWD"), -1);
    char *r = g_strdup_printf("<b>CWD: </b>%s", e);
    g_free(e);
    return r;
}

char *ks_procinfo_parents(const struct ks_procinfo *p)
{
    const cJSON *tree = get(p, "Tree");
    if (!cJSON_IsArray(tree))
        return g_strdup("&lt;could not obtain hash&gt;");
    /* the tree comes child first: reversed, the oldest ancestor is first */
    GPtrArray *keys = g_ptr_array_new_with_free_func(g_free);
    const cJSON *t;
    cJSON_ArrayForEach(t, tree)
    {
        g_ptr_array_insert(keys, 0, g_markup_escape_text(str(t, "key"), -1));
    }
    GString *g = g_string_new("<b>Parent(s): </b>");
    for (guint i = 0; i < keys->len; i++)
        g_string_append_printf(g, "%s%s", i ? " \xe2\x9e\xa1 " : "", (char *)g_ptr_array_index(keys, i));
    g_ptr_array_free(keys, TRUE);
    return g_string_free(g, FALSE);
}

char *ks_procinfo_checksums(const struct ks_procinfo *p)
{
    const cJSON *c = get(p, "Checksums");
    if (!cJSON_IsObject(c))
        return NULL;
    char *r = NULL;
    const cJSON *md5 = cJSON_GetObjectItemCaseSensitive(c, "process.hash.md5");
    const cJSON *sha1 = cJSON_GetObjectItemCaseSensitive(c, "process.hash.sha1");
    /* upstream assigns, it does not append: sha1 wins if both are there */
    if (cJSON_IsString(md5)) {
        char *e = g_markup_escape_text(md5->valuestring, -1);
        r = g_strdup_printf("<b>md5:</b> %s", e);
        g_free(e);
    }
    if (cJSON_IsString(sha1)) {
        char *e = g_markup_escape_text(sha1->valuestring, -1);
        g_free(r);
        r = g_strdup_printf("<b>sha1:</b> %s", e);
        g_free(e);
    }
    return r != NULL ? r : g_strdup("");
}

/* "%d" of (x / 1024) / 1024: truncated */
static long mb(double x)
{
    return (long)((x / 1024) / 1024);
}

char *ks_procinfo_mem(const struct ks_procinfo *p)
{
    const cJSON *m = get(p, "Statm");
    if (!cJSON_IsObject(m))
        return NULL;
    return g_strdup_printf("<b>VIRT:</b> %ldMB, <b>RSS:</b> %ldMB, <b>Libs:</b> %ldMB, "
                           "<b>Data:</b> %ldMB, <b>Text:</b> %ldMB",
                           mb(num(m, "Size")), mb(num(m, "Resident")), mb(num(m, "Lib")),
                           mb(num(m, "Data")), mb(num(m, "Text")));
}

char *ks_procinfo_status(const struct ks_procinfo *p)
{
    return cJSON_IsString(get(p, "Status")) ? g_strdup(str(p->j, "Status")) : NULL;
}

char *ks_procinfo_maps(const struct ks_procinfo *p)
{
    return cJSON_IsString(get(p, "Maps")) ? g_strdup(str(p->j, "Maps")) : NULL;
}

char *ks_procinfo_stack(const struct ks_procinfo *p)
{
    return cJSON_IsString(get(p, "Stack")) ? g_strdup(str(p->j, "Stack")) : NULL;
}

char *ks_procinfo_iostats(const struct ks_procinfo *p)
{
    const cJSON *io = get(p, "IOStats");
    if (!cJSON_IsObject(io))
        return NULL;
    return g_strdup_printf("<b>Chars read:</b> %ldMB\n<b>Chars written:</b> %ldMB\n"
                           "<b>Syscalls read:</b> %ld\n<b>Syscalls write:</b> %ld\n"
                           "<b>KB read:</b> %ldMB\n<b>KB written: </b>%ldMB",
                           mb(num(io, "RChar")), mb(num(io, "WChar")), (long)num(io, "SyscallRead"),
                           (long)num(io, "SyscallWrite"), mb(num(io, "ReadBytes")),
                           mb(num(io, "WriteBytes")));
}

char *ks_procinfo_env(const struct ks_procinfo *p)
{
    const cJSON *env = get(p, "Env");
    if (!cJSON_IsObject(env))
        return NULL;
    if (env->child == NULL)
        return g_strdup("<no environment variables>");
    GString *g = g_string_new(NULL);
    g_string_append_printf(g, "%-15s\t%s\n\n", "Name", "Value");
    const cJSON *e;
    cJSON_ArrayForEach(e, env)
    {
        g_string_append_printf(g, "%-15s:\t%s\n", e->string, cJSON_IsString(e) ? e->valuestring : "");
    }
    return g_string_free(g, FALSE);
}

/* the SOCKET_REGEX "(socket.*:.*state.*)" over the text: every line with
 * "socket", a ":" after it, and "state" after that ("." has no newline) */
static void sockets_in(const char *text, GString *out)
{
    char **lines = g_strsplit(text, "\n", -1);
    for (char **l = lines; *l != NULL; l++) {
        const char *s = *l;
        /* leftmost "socket" with a ':' then "state" after it */
        for (const char *a = strstr(s, "socket"); a != NULL; a = strstr(a + 1, "socket")) {
            const char *c = strchr(a + 6, ':');
            if (c != NULL && strstr(c + 1, "state") != NULL) {
                g_string_append_printf(out, "\n%s", a);
                break;
            }
        }
    }
    g_strfreev(lines);
}

char *ks_procinfo_descriptors(const struct ks_procinfo *p, bool filter_files, bool filter_sockets)
{
    const cJSON *d = get(p, "Descriptors");
    if (!cJSON_IsArray(d))
        return NULL;
    GString *g = g_string_new(NULL);
    g_string_append_printf(g, "%-12s%-40s%-8s -> %s\n\n", "Size", "Time", "Name", "Symlink");
    const cJSON *e;
    cJSON_ArrayForEach(e, d)
    {
        if (filter_files && num(e, "Size") == 0)
            continue;
        g_string_append_printf(g, "%-12ld%-40s%-8s -> %s\n", (long)num(e, "Size"),
                               str(e, "ModTime"), str(e, "Name"), str(e, "SymLink"));
    }
    if (filter_sockets) {
        GString *socks = g_string_new(NULL);
        sockets_in(g->str, socks);
        if (socks->len > 0) {
            if (filter_files) {
                g_string_append(g, socks->str);
            } else {
                g_string_assign(g, socks->str);
            }
        }
        g_string_free(socks, TRUE);
    }
    return g_string_free(g, FALSE);
}
