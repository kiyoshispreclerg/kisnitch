/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port of ui/opensnitch/utils/languages.py (init, get_all) on top of gettext.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/i18n.h"

#include <dirent.h>
#include <glib.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const struct {
    const char *code;
    const char *name;
} native_names[] = {
    {"ar", "العربية"},        {"cs_CZ", "Čeština"},     {"de_DE", "Deutsch"},
    {"es_ES", "Español"},     {"eu_ES", "Euskara"},     {"fi_FI", "Suomi"},
    {"fr_FR", "Français"},    {"he_IL", "עברית"},       {"hi_IN", "हिन्दी"},
    {"hu_HU", "Magyar"},      {"id_ID", "Indonesia"},   {"it_IT", "Italiano"},
    {"ja_JP", "日本語"},      {"lt_LT", "Lietuvių"},    {"nb_NO", "Norsk bokmål"},
    {"nl_NL", "Nederlands"},  {"pt_BR", "Português"},   {"ro_RO", "Română"},
    {"ru_RU", "Русский"},     {"sq_AL", "Shqip"},       {"sv_SE", "Svenska"},
    {"tr_TR", "Türkçe"},      {"uk_UA", "Українська"},  {"zh_CN", "简体中文"},
    {"zh_TW", "繁體中文"},
};

/* The upstream name for Simplified Chinese is zh_Hans; gettext knows it as
 * zh_CN, so a setting written by the original UI keeps working. */
static const char *canonical(const char *lang)
{
    return strcmp(lang, "zh_Hans") == 0 ? "zh_CN" : lang;
}

const char *ks_i18n_native_name(const char *lang)
{
    if (lang == NULL)
        return "";
    if (strcmp(lang, KS_LANG_DEFAULT) == 0)
        return "English";
    lang = canonical(lang);
    for (size_t i = 0; i < sizeof(native_names) / sizeof(native_names[0]); i++)
        if (strcmp(native_names[i].code, lang) == 0)
            return native_names[i].name;
    return lang;
}

static char bound_dir[4096];

static const char *default_dir(void)
{
    const char *env = getenv("KS_LOCALEDIR");
    return (env != NULL && env[0] != '\0') ? env : KS_LOCALEDIR;
}

const char *ks_i18n_localedir(void)
{
    return bound_dir[0] != '\0' ? bound_dir : default_dir();
}

void ks_i18n_init(const char *localedir, const char *lang)
{
    if (localedir == NULL)
        localedir = default_dir();
    snprintf(bound_dir, sizeof(bound_dir), "%s", localedir);

    setlocale(LC_ALL, "");
    if (lang != NULL && lang[0] != '\0') {
        /* LANGUAGE has priority over LANG for the catalogs, but the C
         * locale ignores it: ask for C.UTF-8 (glibc), which doesn't */
        setenv("LANGUAGE", canonical(lang), 1);
        const char *cur = setlocale(LC_MESSAGES, NULL);
        if (cur == NULL || strcmp(cur, "C") == 0 || strcmp(cur, "POSIX") == 0) {
            /* newer glibc may ignore LANGUAGE under C.UTF-8 as well: prefer
             * a real locale when one is installed */
            char want[KS_LANG_MAX + 8];
            snprintf(want, sizeof(want), "%s.UTF-8", canonical(lang));
            if (setlocale(LC_MESSAGES, want) == NULL &&
                setlocale(LC_MESSAGES, "en_US.UTF-8") == NULL)
                setlocale(LC_MESSAGES, "C.UTF-8");
        }
    }
    bindtextdomain(KS_I18N_DOMAIN, localedir);
    bind_textdomain_codeset(KS_I18N_DOMAIN, "UTF-8");
    textdomain(KS_I18N_DOMAIN);
}

static int cmp_lang(const void *a, const void *b)
{
    return strcmp(a, b);
}

size_t ks_i18n_languages(const char *localedir, char out[][KS_LANG_MAX], size_t max)
{
    size_t n = 0;
    if (max == 0)
        return 0;
    snprintf(out[n++], KS_LANG_MAX, "%s", KS_LANG_DEFAULT);
    if (localedir == NULL)
        localedir = ks_i18n_localedir();
    DIR *d = opendir(localedir);
    if (d == NULL)
        return n;
    size_t first = n;
    for (struct dirent *e; (e = readdir(d)) != NULL && n < max;) {
        struct stat st;
        if (e->d_name[0] == '.' || strlen(e->d_name) >= KS_LANG_MAX)
            continue;
        /* only the locales we know, so another package's don't show up */
        if (strcmp(ks_i18n_native_name(e->d_name), e->d_name) == 0)
            continue;
        char *path = g_strdup_printf("%s/%s/LC_MESSAGES/" KS_I18N_DOMAIN ".mo", localedir, e->d_name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
            memcpy(out[n++], e->d_name, strlen(e->d_name) + 1); /* < KS_LANG_MAX, checked above */
        g_free(path);
    }
    closedir(d);
    qsort(out[first], n - first, KS_LANG_MAX, cmp_lang);
    return n;
}
