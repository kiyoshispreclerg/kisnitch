/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/i18n.c with the catalogs msgfmt built from po/ (KS_TEST_LOCALEDIR).
 * The tests that need a catalog are skipped when there is none (no msgfmt).
 */
#include "ui/i18n.h"

#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "tests/harness.h"

static bool have_catalog(const char *lang)
{
    char path[4096];
    struct stat st;
    snprintf(path, sizeof(path), KS_TEST_LOCALEDIR "/%s/LC_MESSAGES/kisnitch.mo", lang);
    return stat(path, &st) == 0;
}

static bool have_c_utf8(void)
{
    char *saved = setlocale(LC_MESSAGES, NULL);
    saved = saved != NULL ? strdup(saved) : NULL;
    bool ok = setlocale(LC_MESSAGES, "C.UTF-8") != NULL;
    if (saved != NULL) {
        setlocale(LC_MESSAGES, saved);
        free(saved);
    }
    return ok;
}

TEST(native_names)
{
    CHECK_STR_EQ(ks_i18n_native_name("en"), "English");
    CHECK_STR_EQ(ks_i18n_native_name("pt_BR"), "Português");
    CHECK_STR_EQ(ks_i18n_native_name("de_DE"), "Deutsch");
    /* the original UI's name for Simplified Chinese */
    CHECK_STR_EQ(ks_i18n_native_name("zh_Hans"), "简体中文");
    CHECK_STR_EQ(ks_i18n_native_name("xx_XX"), "xx_XX");
    CHECK_STR_EQ(ks_i18n_native_name(""), "");
}

TEST(languages)
{
    char langs[64][KS_LANG_MAX];
    size_t n = ks_i18n_languages(KS_TEST_LOCALEDIR, langs, 64);
    CHECK(n >= 1);
    CHECK_STR_EQ(langs[0], "en");
    if (!have_catalog("pt_BR"))
        return;
    bool pt = false;
    for (size_t i = 1; i < n; i++) {
        pt |= strcmp(langs[i], "pt_BR") == 0;
        CHECK(strcmp(langs[i], "en") != 0);
        if (i > 1)
            CHECK(strcmp(langs[i - 1], langs[i]) < 0);
    }
    CHECK(pt);
    /* a directory without catalogs: just English; a missing one too */
    CHECK_INT_EQ((long)ks_i18n_languages("/nonexistent", langs, 64), 1);
    CHECK_INT_EQ((long)ks_i18n_languages(KS_TEST_LOCALEDIR, langs, 1), 1);
}

TEST(translate)
{
    if (!have_catalog("pt_BR") || !have_catalog("de_DE") || !have_c_utf8())
        return;
    setenv("LC_ALL", "C", 1);
    unsetenv("LANGUAGE");

    /* under the C locale, an explicit language still works */
    ks_i18n_init(KS_TEST_LOCALEDIR, "pt_BR");
    const char *cur = setlocale(LC_MESSAGES, NULL);
    if (strcmp(_("Allow"), "Allow") == 0 && cur != NULL && strncmp(cur, "C", 1) == 0) {
        /* glibc 2.39 ignores LANGUAGE under C.UTF-8 too: nothing to test
         * without an installed non-C locale */
        printf("   (this libc ignores LANGUAGE under %s: skipped)\n", cur);
        return;
    }
    CHECK_STR_EQ(_("Allow"), "Permitir");
    CHECK_STR_EQ(_("until reboot"), "até reiniciar");
    /* a text with no translation comes back as is */
    CHECK_STR_EQ(_("No such text in the catalog"), "No such text in the catalog");

    ks_i18n_init(KS_TEST_LOCALEDIR, "de_DE");
    CHECK_STR_EQ(_("Allow"), "Erlauben");

    /* "en": the original text */
    ks_i18n_init(KS_TEST_LOCALEDIR, "en");
    CHECK_STR_EQ(_("Allow"), "Allow");

    /* the original UI wrote "zh_Hans" */
    if (have_catalog("zh_CN")) {
        ks_i18n_init(KS_TEST_LOCALEDIR, "zh_Hans");
        CHECK(strcmp(_("Allow"), "Allow") != 0);
    }
    CHECK_STR_EQ(ks_i18n_localedir(), KS_TEST_LOCALEDIR);
}

int main(void)
{
    RUN(native_names);
    RUN(languages);
    RUN(translate);
    return harness_report();
}
