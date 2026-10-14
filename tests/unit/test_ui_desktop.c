/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ui/desktop.c: .desktop files read as upstream's desktop_parser.py does
 * (Python's configparser). The _parse_exec() expectations come from
 * running upstream's own function with PATH=/usr/bin:/bin.
 */
#include "ui/desktop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/json_util.h"
#include "tests/harness.h"

static char dir[64], apps[96];

static void write_desktop(const char *name, const char *text)
{
    char path[256], err[128];
    snprintf(path, sizeof(path), "%s/%s", apps, name);
    ks_write_file(path, text, strlen(text), 0644, err, sizeof(err));
}

TEST(parse_exec)
{
    static const struct {
        const char *in, *out;
    } cases[] = {
        {"/usr/bin/firefox %u", "/usr/bin/firefox"},
        {"env GDK_BACKEND=x11 /usr/bin/app --flag", "/usr/bin/app"},
        {"\"/opt/My App/bin/app\" %F", "/opt/My"},
        {"'/usr/bin/quoted'", "/usr/bin/quoted"},
        {"/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=com.app.Bin org.app",
         "com.app.Bin"},
        {"/usr/sbin/flatpak run --command=a --command=/app/bin/b x", "/app/bin/b"},
        {"/usr/bin/flatpak run --command= org.x", "/usr/bin/flatpak"},
        {"sh -c \"echo hi\"", "/usr/bin/sh"},
        {"nonexistentbinary123 --x", "nonexistentbinary123"},
        {"  /usr/bin/spaced  ", ""},
        {"%f", ""},
        {"", ""},
        {"env", "/usr/bin/env"},
        {"env x", "/usr/bin/env"},
        {"ls", "/usr/bin/ls"},
        {"/usr/bin/x%%y", "/usr/bin/x%"},
        {"/usr/bin/a%Ub", "/usr/bin/a"},
        {"env FOO=bar", "/usr/bin/env"},
    };
    char *old = strdup(getenv("PATH") ? getenv("PATH") : "");
    setenv("PATH", "/usr/bin:/bin", 1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *o = ks_desktop_parse_exec(cases[i].in);
        CHECK_MSG(o != NULL && strcmp(o, cases[i].out) == 0, "_parse_exec(%s) = \"%s\"",
                  cases[i].in, o ? o : "(null)");
        free(o);
    }
    setenv("PATH", old, 1);
    free(old);
}

TEST(desktop_files)
{
    char real[256], link[256], text[1024];
    snprintf(real, sizeof(real), "%s/real-bin", dir);
    snprintf(link, sizeof(link), "%s/link-bin", dir);
    FILE *f = fopen(real, "w");
    CHECK(f != NULL);
    fclose(f);
    CHECK(symlink(real, link) == 0);

    write_desktop("app.desktop", "# comment\n"
                                 "[Desktop Entry]\n"
                                 "Name=Test App\n"
                                 "Exec=/usr/bin/testapp %U\n"
                                 "Icon=testicon\n"
                                 "Comment=Generic\n"
                                 "Comment[pt]=Portugu\xc3\xaas\n"
                                 "Comment[pt_BR]=Brasil\n"
                                 "\n"
                                 "[Desktop Action new]\n"
                                 "Name=Other section\n");
    write_desktop("dup.desktop", "[Desktop Entry]\n"
                                 "exec=/usr/bin/first\n"
                                 "Name = Dup\n"
                                 "Exec=/usr/bin/second\n"
                                 "Comment=line one\n"
                                 "   line two\n"
                                 "Icon=dup\n");
    write_desktop("bad.desktop", "Name=No section\n[Desktop Entry]\nExec=/usr/bin/bad\n");
    write_desktop("bad2.desktop", "[Desktop Entry]\nExec=/usr/bin/bad2\nno delimiter here\n");
    write_desktop("flat.desktop", "[Desktop Entry]\nName=flatpak\nExec=/usr/bin/flatty\n");
    write_desktop("zzqqnoicon.desktop", "[Desktop Entry]\nName=No Icon\nExec=/usr/bin/zzq\n");
    snprintf(text, sizeof(text), "[Desktop Entry]\nName=Linked\nExec=%s\nIcon=l\n", link);
    write_desktop("linked.desktop", text);
    write_desktop("noexec.desktop", "[Desktop Entry]\nName=No Exec\n");
    write_desktop("ignored.txt", "[Desktop Entry]\nName=Txt\nExec=/usr/bin/txt\n");

    struct ks_desktop d;
    CHECK(ks_desktop_init(&d, dir, "pt_BR.UTF-8") == 0);
    CHECK_STR_EQ(d.locale, "pt_BR");
    CHECK_STR_EQ(d.locale_country, "pt");

    struct ks_app_info *i = ks_desktop_info_by_path(&d, "/usr/bin/testapp", "def");
    CHECK_STR_EQ(i->name, "Test App");
    CHECK_STR_EQ(i->icon, "testicon");
    CHECK_STR_EQ(i->description, "Portugu\xc3\xaas"); /* Comment[<language>] first */
    CHECK_STR_HAS(i->desktop_path, "/applications/app.desktop");
    ks_app_info_free(i);
    /* by the .desktop file's basename, whatever the directory */
    i = ks_desktop_info_by_path(&d, "/somewhere/else/app", "def");
    CHECK_STR_EQ(i->name, "Test App");
    ks_app_info_free(i);

    i = ks_desktop_info_by_path(&d, "/usr/bin/second", "def");
    CHECK_STR_EQ(i->name, "Dup");
    CHECK_STR_EQ(i->description, "line one\nline two");
    ks_app_info_free(i);
    i = ks_desktop_info_by_path(&d, "/usr/bin/first", "def");
    CHECK_STR_EQ(i->name, "first"); /* replaced by the later Exec */
    ks_app_info_free(i);

    i = ks_desktop_info_by_path(&d, "/usr/bin/bad", "def");
    CHECK_STR_EQ(i->name, "bad"); /* the file was skipped: the default */
    CHECK(i->desktop_path == NULL);
    ks_app_info_free(i);
    i = ks_desktop_info_by_path(&d, "/usr/bin/bad2", "def");
    CHECK(i->desktop_path == NULL);
    ks_app_info_free(i);
    i = ks_desktop_info_by_path(&d, "/usr/bin/flatty", "def");
    CHECK(i->desktop_path == NULL);
    ks_app_info_free(i);
    i = ks_desktop_info_by_path(&d, "/usr/bin/txt", "def");
    CHECK(i->desktop_path == NULL);
    ks_app_info_free(i);

    i = ks_desktop_info_by_path(&d, "/usr/bin/zzq", "def");
    CHECK_STR_EQ(i->name, "No Icon");
    CHECK_STR_EQ(i->icon, KS_DESKTOP_TERMINAL_ICON);
    CHECK_STR_EQ(i->description, "");
    ks_app_info_free(i);

    /* a symlinked Exec also answers for its target */
    i = ks_desktop_info_by_path(&d, real, "def");
    CHECK_STR_EQ(i->name, "Linked");
    ks_app_info_free(i);

    i = ks_desktop_info_by_path(&d, "/usr/bin/zzunknownbin", "def");
    CHECK_STR_EQ(i->name, "zzunknownbin");
    CHECK_STR_EQ(i->icon, KS_DESKTOP_TERMINAL_ICON);
    ks_app_info_free(i);

    /* a changed file is read again (inotify) */
    int fd = ks_desktop_watch(&d);
    CHECK(fd >= 0);
    write_desktop("new.desktop", "[Desktop Entry]\nName=New One\nExec=/usr/bin/newone\n");
    ks_desktop_on_inotify(&d);
    i = ks_desktop_info_by_path(&d, "/usr/bin/newone", "def");
    CHECK_STR_EQ(i->name, "New One");
    ks_app_info_free(i);
    ks_desktop_free(&d);

    /* without the language variant */
    CHECK(ks_desktop_init(&d, dir, "de_DE") == 0);
    i = ks_desktop_info_by_path(&d, "/usr/bin/testapp", "def");
    CHECK_STR_EQ(i->description, "Generic");
    ks_app_info_free(i);
    ks_desktop_free(&d);
    CHECK(ks_desktop_init(&d, dir, "") == 0);
    ks_desktop_free(&d);

    unlink(real);
    unlink(link);
}

TEST(fixes)
{
    struct ks_desktop d;
    write_desktop("ff.desktop", "[Desktop Entry]\nName=Firefox\nExec=/usr/lib/firefox/firefox.sh\n");
    CHECK(ks_desktop_init(&d, dir, "C") == 0);
    struct ks_app_info *i = ks_desktop_info_by_path(&d, "/usr/lib/firefox/firefox", "def");
    CHECK_STR_EQ(i->name, "Firefox");
    ks_app_info_free(i);
    ks_desktop_free(&d);
}

int main(void)
{
    snprintf(dir, sizeof(dir), "/tmp/ks-desktop-XXXXXX");
    if (mkdtemp(dir) == NULL)
        return 1;
    snprintf(apps, sizeof(apps), "%s/applications", dir);
    mkdir(apps, 0755);
    RUN(parse_exec);
    RUN(desktop_files);
    RUN(fixes);
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0)
        return 1;
    return harness_report();
}
