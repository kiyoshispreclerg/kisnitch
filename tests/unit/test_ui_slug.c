/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/slug.c against python-slugify: the expected values were produced by
 * slugify() itself (python-slugify 4.0, Unidecode 1.3). Characters outside
 * the generated tables (CJK, for one) are a known divergence and not
 * listed.
 */
#include "ui/slug.h"

#include <stdlib.h>

#include "tests/harness.h"

static const struct {
    const char *in, *out;
} cases[] = {
    {"allow always", "allow-always"},
    {"deny 30s", "deny-30s"},
    {"allow-always-simple /usr/bin/curl", "allow-always-simple-usr-bin-curl"},
    {"reject until restart", "reject-until-restart"},
    {"allow-once-list /home/jo\303\243o/\303\201rea de Trabalho/app", "allow-once-list-home-joao-area-de-trabalho-app"},
    {"Stra\303\237e \303\237", "strasse-ss"},
    {"caf\303\251&eacute;s", "cafee-s"},
    {"a&amp;b", "a-b"},
    {"&#65;&#x42;", "ab"},
    {"&#1114112;&#65;", "1114112-65"},
    {"x&#39;y", "xy"},
    {"it's a 'quote'", "it-s-a-quote"},
    {"1,000,000 and 1,a", "1000000-and-1-a"},
    {"1',2", "1-2"},
    {"--a--b--", "a-b"},
    {"  spaces  ", "spaces"},
    {"UPPER lower 123", "upper-lower-123"},
    {"\342\202\254100 \302\267 \302\275 \302\262", "eur100-1-2-2"},
    {"/tmp/.mount_abc/usr/bin/x", "tmp-mount-abc-usr-bin-x"},
    {"^(|.*\\.)example\\.com$", "example-com"},
    {"10.0.0.0/8", "10-0-0-0-8"},
    {"2001:db8::/64", "2001-db8-64"},
    {"&notin;&not;x", "x"},
    {"&amp;#65;", "a"},
    {"allow-always-list-usr-bin-curl 1.2.3.4", "allow-always-list-usr-bin-curl-1-2-3-4"},
    {"\303\206sir \307\242 \307\243", "aesir-ae-ae"},
    {"tab\011new\012line", "tab-new-line"},
    {"&Eacute;cole", "e-cole"},
    {"\357\254\201 ligature", "fi-ligature"},
    {"x&#x1F600;y", "x-y"},
    {"&#0;z", "z"},
    {"&#x110000;&#x41;", "x110000-x41"},
    {"\316\225\316\273\316\273\316\267\316\275\316\271\316\272\316\254 \320\232\320\270\321\200\320\270\320\273\320\273\320\270\321\206\320\260", "ellenika-kirillitsa"},
    {"\357\274\246\357\274\265\357\274\254\357\274\254", "full"},
    {"\342\204\242 \342\204\203 \342\204\226", "tm-no"},
    {"", ""},
    {"---", ""},
    {"&;&#;&#x;", "x"},
    {"&AMP;", "amp"},
    {"&lt;b&gt;", "b"},
    {"allow-12h-list [{\"type\": \"simple\", \"operand\": \"dest.ip\", \"data\": \"127.0.0.1\"}]", "allow-12h-list-type-simple-operand-dest-ip-data-127-0-0-1"},
    {"deny-forever-simple ^\\/snap\\/firefox\\/[0-9]+\\/usr\\/lib\\/firefox$", "deny-forever-simple-snap-firefox-0-9-usr-lib-firefox"},
};

TEST(matches_python_slugify)
{
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *s = ks_slugify(cases[i].in);
        CHECK(s != NULL);
        CHECK_MSG(strcmp(s, cases[i].out) == 0, "slugify(\"%s\") = \"%s\", want \"%s\"",
                  cases[i].in, s, cases[i].out);
        free(s);
    }
}

TEST(invalid_utf8_does_not_crash)
{
    char *s = ks_slugify("a\xff\xfe b\xc3");
    CHECK(s != NULL);
    CHECK_STR_EQ(s, "a-b");
    free(s);
}

int main(void)
{
    RUN(matches_python_slugify);
    RUN(invalid_utf8_does_not_crash);
    return harness_report();
}
