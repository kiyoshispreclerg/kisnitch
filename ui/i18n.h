/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Translations of the UI with gettext. Upstream uses Qt's QTranslator with
 * .qm files loaded from ui/opensnitch/i18n/<locale>/opensnitch-<locale>.qm
 * (ui/opensnitch/utils/languages.py); here the same locales are .po files in
 * po/ (converted from the upstream .ts by tools/ts2po.py), installed as
 * <localedir>/<locale>/LC_MESSAGES/kisnitch.mo.
 *
 * The message id is the English text, as in Qt's tr(): mark a literal with
 * _() where it is used, or with N_() where it is stored (a static table)
 * and pass it through _() when it is shown.
 *
 * The language is the "global/language" setting ("" or unset: the system's;
 * "en": none). Changing it takes effect on the next start, as upstream
 * ("Language changed" asks for a restart).
 *
 * Memory: nothing is owned by the caller; the strings from _() belong to
 * libintl and live until the next ks_i18n_init().
 */
#ifndef KS_UI_I18N_H
#define KS_UI_I18N_H

#include <libintl.h>
#include <stddef.h>

#define KS_I18N_DOMAIN "kisnitch"
#define KS_LANG_DEFAULT "en"
#define KS_LANG_MAX 16

#ifndef KS_LOCALEDIR
#define KS_LOCALEDIR "/usr/local/share/locale"
#endif

#define _(s) gettext(s)
#define N_(s) (s)

/* Binds the catalog in `localedir` (NULL: KS_LOCALEDIR, or $KS_LOCALEDIR)
 * and selects `lang` ("pt_BR", "zh_Hans"...; NULL or "": the system's,
 * "en": untranslated). Needs setlocale() to have run (gtk_init does).
 * Under the C locale the translations still work for an explicit language
 * (LC_MESSAGES is switched to C.UTF-8). */
void ks_i18n_init(const char *localedir, const char *lang);

/* The directory bound by the last ks_i18n_init() (or the default one). */
const char *ks_i18n_localedir(void);

/* Locales that have a catalog in `localedir`, sorted, "en" first (as
 * languages.get_all()). Fills `out` (up to `max`) and returns the count. */
size_t ks_i18n_languages(const char *localedir, char out[][KS_LANG_MAX], size_t max);

/* The name of a locale in its own language (QLocale.nativeLanguageName),
 * or the code itself when it isn't in the table. */
const char *ks_i18n_native_name(const char *lang);

#endif /* KS_UI_I18N_H */
