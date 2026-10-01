/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Evaluates the differential corpus with Kisnitch's rules engine and writes
 * one "<id> <result>" line per case, like tests/diff/go/main.go does with
 * upstream's code. tests/diff/run.sh compares both outputs.
 *
 * Usage (from the repository root): ks_diff tests/diff/corpus.json out.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/json_util.h"
#include "common/log.h"
#include "daemon/rules/aliases.h"
#include "daemon/rules/loader.h"
#include "daemon/rules/rule.h"

/* Connections and processes built from the corpus; never freed (the
 * program is short-lived). */
static struct ks_process *mk_proc(const cJSON *j)
{
    if (j == NULL || cJSON_IsNull(j))
        return NULL;
    struct ks_process *p = calloc(1, sizeof(*p));
    p->pid = cJSON_GetObjectItemCaseSensitive(j, "pid")->valueint;
    p->path = cJSON_GetObjectItemCaseSensitive(j, "path")->valuestring;

    const cJSON *args = cJSON_GetObjectItemCaseSensitive(j, "args");
    p->nargs = (size_t)cJSON_GetArraySize(args);
    const char **a = calloc(p->nargs + 1, sizeof(*a));
    size_t i = 0;
    const cJSON *it;
    cJSON_ArrayForEach(it, args) a[i++] = it->valuestring;
    p->args = a;

    const cJSON *env = cJSON_GetObjectItemCaseSensitive(j, "env");
    p->nenv = (size_t)cJSON_GetArraySize(env);
    struct ks_env_var *e = calloc(p->nenv + 1, sizeof(*e));
    i = 0;
    cJSON_ArrayForEach(it, env) {
        e[i].name = it->string;
        e[i].value = it->valuestring;
        i++;
    }
    p->env = e;

    const cJSON *sums = cJSON_GetObjectItemCaseSensitive(j, "checksums");
    const cJSON *md5 = cJSON_GetObjectItemCaseSensitive(sums, "process.hash.md5");
    const cJSON *sha1 = cJSON_GetObjectItemCaseSensitive(sums, "process.hash.sha1");
    p->checksum_md5 = md5 ? md5->valuestring : NULL;
    p->checksum_sha1 = sha1 ? sha1->valuestring : NULL;
    p->parent = mk_proc(cJSON_GetObjectItemCaseSensitive(j, "parent"));
    return p;
}

static const struct ks_process empty_proc = {0};

static struct ks_conn mk_conn(const cJSON *j)
{
    struct ks_conn c;
    memset(&c, 0, sizeof(c));
    c.protocol = cJSON_GetObjectItemCaseSensitive(j, "protocol")->valuestring;
    c.dst_host = cJSON_GetObjectItemCaseSensitive(j, "dst_host")->valuestring;
    /* net.ParseIP gives nil (len 0) on errors, as ks_ip_parse leaves it. */
    ks_ip_parse(cJSON_GetObjectItemCaseSensitive(j, "src_ip")->valuestring, &c.src_ip);
    ks_ip_parse(cJSON_GetObjectItemCaseSensitive(j, "dst_ip")->valuestring, &c.dst_ip);
    c.src_port = (unsigned)cJSON_GetObjectItemCaseSensitive(j, "src_port")->valuedouble;
    c.dst_port = (unsigned)cJSON_GetObjectItemCaseSensitive(j, "dst_port")->valuedouble;
    c.iface_in = cJSON_GetObjectItemCaseSensitive(j, "iface_in")->valueint;
    c.iface_out = cJSON_GetObjectItemCaseSensitive(j, "iface_out")->valueint;
    c.uid = cJSON_GetObjectItemCaseSensitive(j, "uid")->valueint;
    c.process = mk_proc(cJSON_GetObjectItemCaseSensitive(j, "process"));
    if (c.process == NULL)
        c.process = &empty_proc;
    return c;
}

/* What the loader does with a rule's operator. */
static const char *eval_operator(const char *json, const struct ks_conn *c,
                                 bool has_checksums,
                                 const struct ks_rules_env *env)
{
    char err[512];
    struct ks_array arr;
    size_t n = strlen(json);
    char *wrapped = malloc(n + 3);
    snprintf(wrapped, n + 3, "[%s]", json);
    int rc = ks_operator_list_parse(wrapped, &arr, err, sizeof(err));
    free(wrapped);
    if (rc < 0 || arr.len != 1)
        return "parse-error";
    struct ks_operator *o = KS_ARRAY_ITEM(arr, struct ks_operator, 0);

    const char *res;
    if (ks_operator_compile(o, env, err, sizeof(err)) < 0) {
        res = "compile-error";
        goto out;
    }
    if (strcmp(o->type, KS_TYPE_LIST) == 0) {
        for (size_t i = 0; i < o->list.len; i++)
            if (ks_operator_compile(KS_ARRAY_ITEM(o->list, struct ks_operator, i),
                                    env, err, sizeof(err)) < 0) {
                res = "compile-error";
                goto out;
            }
    }
    res = ks_operator_match(o, c, has_checksums) ? "match" : "nomatch";
out:
    ks_operator_clear(o);
    free(arr.items);
    return res;
}

static void eval_ruleset(const cJSON *rs, const struct ks_conn *c,
                         const struct ks_aliases *aliases, char *out, size_t len)
{
    char dir[] = "/tmp/ksdiff-XXXXXX";
    char err[512], path[64];
    if (mkdtemp(dir) == NULL) {
        snprintf(out, len, "tmpdir-error");
        return;
    }
    int i = 0;
    const cJSON *r;
    cJSON_ArrayForEach(r, cJSON_GetObjectItemCaseSensitive(rs, "rules")) {
        char *json = cJSON_PrintUnformatted(r);
        snprintf(path, sizeof(path), "%s/%03d.json", dir, i++);
        ks_write_file(path, json, strlen(json), 0600, err, sizeof(err));
        free(json);
    }
    struct ks_loader *l = ks_loader_new(NULL, aliases, false);
    if (ks_loader_load(l, dir, err, sizeof(err)) < 0) {
        snprintf(out, len, "load-error");
    } else {
        const struct ks_rule *m = ks_loader_find_first_match(l, c);
        snprintf(out, len, "%s n=%zu", m ? m->name : "<nil>", ks_loader_num_rules(l));
    }
    ks_loader_free(l);
    for (int k = 0; k < i; k++) {
        snprintf(path, sizeof(path), "%s/%03d.json", dir, k);
        unlink(path);
    }
    rmdir(dir);
}

int main(int argc, char **argv)
{
    char err[512];
    size_t len;

    if (argc != 3) {
        fprintf(stderr, "usage: ks_diff corpus.json out.txt\n");
        return 2;
    }
    ks_log_set_level(KS_LOG_FATAL + 1);

    char *raw = ks_read_file(argv[1], 64u << 20, &len, err, sizeof(err));
    cJSON *corpus = raw ? ks_json_parse(raw, len, err, sizeof(err)) : NULL;
    if (corpus == NULL) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }
    struct ks_aliases aliases = {0};
    const char *apath = cJSON_GetObjectItemCaseSensitive(corpus, "aliases")->valuestring;
    if (ks_aliases_load(&aliases, apath, err, sizeof(err)) < 0) {
        fprintf(stderr, "aliases: %s\n", err);
        return 1;
    }
    struct ks_rules_env env = {NULL, &aliases};
    const cJSON *conns = cJSON_GetObjectItemCaseSensitive(corpus, "conns");

    FILE *out = fopen(argv[2], "w");
    if (out == NULL) {
        perror(argv[2]);
        return 1;
    }

    const cJSON *k;
    cJSON_ArrayForEach(k, cJSON_GetObjectItemCaseSensitive(corpus, "cases")) {
        const char *cname = cJSON_GetObjectItemCaseSensitive(k, "conn")->valuestring;
        struct ks_conn c = mk_conn(cJSON_GetObjectItemCaseSensitive(conns, cname));
        struct ks_process p;
        const cJSON *path = cJSON_GetObjectItemCaseSensitive(k, "path");
        if (path != NULL) {
            p = *c.process;
            p.path = path->valuestring;
            c.process = &p;
        }
        char *op = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(k, "operator"));
        bool chk = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(k, "has_checksums"));
        fprintf(out, "%s %s\n", cJSON_GetObjectItemCaseSensitive(k, "id")->valuestring,
                eval_operator(op, &c, chk, &env));
        free(op);
    }

    const cJSON *b = cJSON_GetObjectItemCaseSensitive(corpus, "regex_battery");
    const char *bconn = cJSON_GetObjectItemCaseSensitive(b, "conn")->valuestring;
    struct ks_conn bc = mk_conn(cJSON_GetObjectItemCaseSensitive(conns, bconn));
    struct ks_process bp = *bc.process;
    bc.process = &bp;
    int pi = 0;
    const cJSON *pat;
    cJSON_ArrayForEach(pat, cJSON_GetObjectItemCaseSensitive(b, "patterns")) {
        int si = 0;
        const cJSON *subj;
        cJSON_ArrayForEach(subj, cJSON_GetObjectItemCaseSensitive(b, "subjects")) {
            for (int sens = 1; sens >= 0; sens--) {
                cJSON *op = cJSON_CreateObject();
                cJSON_AddStringToObject(op, "type", "regexp");
                cJSON_AddStringToObject(op, "operand", "process.path");
                cJSON_AddStringToObject(op, "data", pat->valuestring);
                cJSON_AddBoolToObject(op, "sensitive", sens);
                char *json = cJSON_PrintUnformatted(op);
                cJSON_Delete(op);
                bp.path = subj->valuestring;
                fprintf(out, "re-%d-%d-%s %s\n", pi, si, sens ? "s" : "i",
                        eval_operator(json, &bc, false, &env));
                free(json);
            }
            si++;
        }
        pi++;
    }

    const cJSON *rs;
    cJSON_ArrayForEach(rs, cJSON_GetObjectItemCaseSensitive(corpus, "rulesets")) {
        const char *cname = cJSON_GetObjectItemCaseSensitive(rs, "conn")->valuestring;
        struct ks_conn c = mk_conn(cJSON_GetObjectItemCaseSensitive(conns, cname));
        char res[256];
        eval_ruleset(rs, &c, &aliases, res, sizeof(res));
        fprintf(out, "%s %s\n", cJSON_GetObjectItemCaseSensitive(rs, "id")->valuestring,
                res);
    }

    fclose(out);
    ks_aliases_free(&aliases);
    cJSON_Delete(corpus);
    free(raw);
    return 0;
}
