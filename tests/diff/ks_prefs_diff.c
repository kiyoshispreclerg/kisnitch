/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Our side of the preferences differential test
 * (tests/diff/prefs/run.sh): reads the cases of gen_cases.py and writes, for
 * each, what ui/prefs_node.c gives, in the format of
 * tests/diff/prefs/upstream_prefs.py (json.dumps, sorted keys).
 *
 *   ks_prefs_diff <cases> <out>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/json_util.h"
#include "ui/prefs_node.h"
#include "ui/pyjson.h"

#define ADDR "unix:/local"

static const char *jstr(const cJSON *o, const char *k, const char *def)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(v) ? v->valuestring : def;
}

static int by_key(const void *a, const void *b)
{
    return strcmp((*(const cJSON *const *)a)->string, (*(const cJSON *const *)b)->string);
}

static void sort_keys(cJSON *o)
{
    if (cJSON_IsArray(o)) {
        for (cJSON *c = o->child; c != NULL; c = c->next)
            sort_keys(c);
        return;
    }
    if (!cJSON_IsObject(o))
        return;
    int n = cJSON_GetArraySize(o), i = 0;
    cJSON **v = calloc((size_t)(n ? n : 1), sizeof(*v));
    for (cJSON *c = o->child; c != NULL; c = c->next)
        v[i++] = c;
    for (i = 0; i < n; i++)
        cJSON_DetachItemViaPointer(o, v[i]);
    qsort(v, (size_t)n, sizeof(*v), by_key);
    for (i = 0; i < n; i++) {
        sort_keys(v[i]);
        cJSON_AddItemToObject(o, v[i]->string, v[i]);
    }
    free(v);
}

static cJSON *form_out(const struct ks_nform *f)
{
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "labelNodeVersion", f->version);
    cJSON_AddStringToObject(j, "labelNodeName", f->name);
    cJSON_AddStringToObject(j, "lineNodeCACertFile", f->ca_cert);
    cJSON_AddStringToObject(j, "lineNodeServerCertFile", f->server_cert);
    cJSON_AddStringToObject(j, "lineNodeCertFile", f->client_cert);
    cJSON_AddStringToObject(j, "lineNodeCertKeyFile", f->client_key);
    cJSON_AddStringToObject(j, "lineNodeRulesPath", f->rules_path);
    cJSON_AddStringToObject(j, "lineNodeFwMonInterval", f->fw_interval);
    cJSON_AddStringToObject(j, "lineNodeMaxEvents", f->max_events);
    cJSON_AddStringToObject(j, "lineNodeMaxStats", f->max_stats);
    cJSON_AddBoolToObject(j, "checkInterceptUnknown", f->intercept_unknown);
    cJSON_AddBoolToObject(j, "checkNodeLogUTC", f->log_utc);
    cJSON_AddBoolToObject(j, "checkNodeLogMicro", f->log_micro);
    cJSON_AddBoolToObject(j, "checkNodeAuthSkipVerify", f->skip_verify);
    cJSON_AddBoolToObject(j, "enableChecksums", f->checksums);
    cJSON_AddBoolToObject(j, "checkNodeFlushConns", f->flush_conns);
    cJSON_AddBoolToObject(j, "checkNodeBypassQueue", f->block_on_fail);
    cJSON_AddNumberToObject(j, "spinNodeGC", f->gc);
    cJSON_AddNumberToObject(j, "comboNodeAction", f->action);
    cJSON_AddNumberToObject(j, "comboNodeMonitorMethod", f->monitor);
    cJSON_AddNumberToObject(j, "comboNodeLogLevel", f->log_level);
    cJSON_AddNumberToObject(j, "comboNodeAuthType", f->auth_type);
    cJSON_AddNumberToObject(j, "comboNodeAuthVerifyType", f->verify_type);
    cJSON_AddStringToObject(j, "comboNodeAddress", f->address);
    cJSON_AddBoolToObject(j, "comboNodeAddress_enabled", f->server_enabled);
    cJSON_AddStringToObject(j, "comboNodeLogFile", f->log_file);
    cJSON_AddBoolToObject(j, "comboNodeLogFile_enabled", f->server_enabled);
    cJSON_AddBoolToObject(j, "lineNodeCACertFile_enabled", f->ca_enabled);
    cJSON_AddBoolToObject(j, "lineNodeServerCertFile_enabled", f->certs_enabled);
    cJSON_AddBoolToObject(j, "lineNodeCertFile_enabled", f->certs_enabled);
    cJSON_AddBoolToObject(j, "lineNodeCertKeyFile_enabled", f->certs_enabled);
    cJSON_AddBoolToObject(j, "checkNodeAuthSkipVerify_enabled", f->certs_enabled);
    cJSON_AddBoolToObject(j, "comboNodeAuthVerifyType_enabled", f->certs_enabled);
    cJSON_AddBoolToObject(j, "needs_update", f->needs_update);
    return j;
}

/* the widgets a "build" case sets */
static void fill(struct ks_nform *f, const cJSON *form)
{
    const cJSON *it;
    cJSON_ArrayForEach(it, form)
    {
        const char *k = it->string;
        if (strcmp(k, "comboNodeAction") == 0) f->action = (int)it->valuedouble;
        else if (strcmp(k, "comboNodeMonitorMethod") == 0) f->monitor = (int)it->valuedouble;
        else if (strcmp(k, "comboNodeLogLevel") == 0) f->log_level = (int)it->valuedouble;
        else if (strcmp(k, "comboNodeAuthType") == 0) f->auth_type = (int)it->valuedouble;
        else if (strcmp(k, "comboNodeAuthVerifyType") == 0) f->verify_type = (int)it->valuedouble;
        else if (strcmp(k, "spinNodeGC") == 0) f->gc = (int)it->valuedouble;
        else if (strcmp(k, "comboNodeAddress") == 0) ks_nform_set(&f->address, it->valuestring);
        else if (strcmp(k, "comboNodeLogFile") == 0) ks_nform_set(&f->log_file, it->valuestring);
        else if (strcmp(k, "lineNodeCACertFile") == 0) ks_nform_set(&f->ca_cert, it->valuestring);
        else if (strcmp(k, "lineNodeServerCertFile") == 0) ks_nform_set(&f->server_cert, it->valuestring);
        else if (strcmp(k, "lineNodeCertFile") == 0) ks_nform_set(&f->client_cert, it->valuestring);
        else if (strcmp(k, "lineNodeCertKeyFile") == 0) ks_nform_set(&f->client_key, it->valuestring);
        else if (strcmp(k, "lineNodeRulesPath") == 0) ks_nform_set(&f->rules_path, it->valuestring);
        else if (strcmp(k, "lineNodeFwMonInterval") == 0) ks_nform_set(&f->fw_interval, it->valuestring);
        else if (strcmp(k, "lineNodeMaxEvents") == 0) ks_nform_set(&f->max_events, it->valuestring);
        else if (strcmp(k, "lineNodeMaxStats") == 0) ks_nform_set(&f->max_stats, it->valuestring);
        else if (strcmp(k, "checkInterceptUnknown") == 0) f->intercept_unknown = cJSON_IsTrue(it);
        else if (strcmp(k, "checkNodeLogUTC") == 0) f->log_utc = cJSON_IsTrue(it);
        else if (strcmp(k, "checkNodeLogMicro") == 0) f->log_micro = cJSON_IsTrue(it);
        else if (strcmp(k, "checkNodeAuthSkipVerify") == 0) f->skip_verify = cJSON_IsTrue(it);
        else if (strcmp(k, "enableChecksums") == 0) f->checksums = cJSON_IsTrue(it);
        else if (strcmp(k, "checkNodeFlushConns") == 0) f->flush_conns = cJSON_IsTrue(it);
        else if (strcmp(k, "checkNodeBypassQueue") == 0) f->block_on_fail = cJSON_IsTrue(it);
    }
}

static cJSON *run_case(const cJSON *c)
{
    const char *kind = jstr(c, "kind", "");
    cJSON *out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "id", jstr(c, "id", ""));
    struct ks_nform f;
    ks_nform_init(&f);
    char err[400] = "";
    if (strcmp(kind, "load") == 0) {
        const char *config = jstr(c, "config", "");
        char *norm = NULL;
        const cJSON *ll = cJSON_GetObjectItemCaseSensitive(c, "loglevel");
        bool ok = ks_prefs_load_node(&f, jstr(c, "version", ""), jstr(c, "name", ""),
                                     (unsigned)(ll ? ll->valuedouble : 0), config, &norm, err,
                                     sizeof(err));
        char status[500] = "";
        if (!ok)
            snprintf(status, sizeof(status), "Error loading config %s: %s", ADDR, err);
        cJSON_AddItemToObject(out, "form", form_out(&f));
        cJSON_AddStringToObject(out, "status", status);
        cJSON_AddStringToObject(out, "config", ok ? norm : config);
        free(norm);
    } else {
        fill(&f, cJSON_GetObjectItemCaseSensitive(c, "form"));
        const cJSON *cfg = cJSON_GetObjectItemCaseSensitive(c, "config");
        char *res = NULL;
        bool ok;
        ok = ks_prefs_build_node(&f, ADDR, cJSON_IsString(cfg) ? cfg->valuestring : NULL, &res, err,
                                 sizeof(err));
        cJSON_AddItemToObject(out, "out", ok ? cJSON_CreateString(res) : cJSON_CreateNull());
        cJSON_AddItemToObject(out, "error", ok ? cJSON_CreateNull() : cJSON_CreateString(err));
        cJSON_AddItemToObject(out, "form", form_out(&f));
        free(res);
    }
    ks_nform_free(&f);
    return out;
}

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    FILE *in = fopen(argv[1], "r");
    FILE *outf = fopen(argv[2], "w");
    if (in == NULL || outf == NULL)
        return 1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, in)) > 0) {
        if (len == 1)
            continue;
        char err[128];
        cJSON *c = ks_json_parse(line, (size_t)len, err, sizeof(err));
        if (c == NULL)
            return 1;
        cJSON *o = run_case(c);
        sort_keys(o);
        char *s = ks_pyjson_dumps(o);
        fprintf(outf, "%s\n", s);
        free(s);
        cJSON_Delete(o);
        cJSON_Delete(c);
    }
    free(line);
    fclose(in);
    fclose(outf);
    return 0;
}
