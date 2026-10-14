/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Application names, icons and descriptions from the .desktop files, to
 * show who is connecting in the pop-up. Port of upstream
 * ui/opensnitch/desktop_parser.py (LinuxDesktopParser): the files in
 * $XDG_DATA_DIRS/applications (/usr/share/applications by default) are
 * read with configparser's rules, their Exec turned into a binary path,
 * and each app is found by that path, its basename and, for symlinks, the
 * real path. Changed files are read again (inotify).
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_desktop owns the apps (shared between their keys,
 * refcounted) and the inotify fd. struct ks_app_info returned by lookups
 * is owned by the caller (ks_app_info_free).
 */
#ifndef KS_UI_DESKTOP_H
#define KS_UI_DESKTOP_H

#include <stdbool.h>
#include <stddef.h>

#include "common/strmap.h"

/* The icon used when an app has none: upstream's res/terminal.svg; here
 * the theme icon of the same meaning. */
#define KS_DESKTOP_TERMINAL_ICON "utilities-terminal"
/* where discover_app_icon() looks: <dir>/<theme>/<size>/apps/ */
#define KS_DESKTOP_ICONS_DIR "/usr/share/icons"

struct ks_desktop {
    struct ks_strmap apps;
    char locale[64];         /* "pt_BR" */
    char locale_country[16]; /* "pt" */
    char **dirs;             /* the applications directories */
    int ndirs;
    int inotify_fd;
    int *wds;
    const char *icons_dir; /* KS_DESKTOP_ICONS_DIR; tests change it */
};

struct ks_app_info {
    char *name;
    char *icon; /* theme name or absolute path */
    char *description;
    char *desktop_path; /* NULL if not from a .desktop file */
};

/* Reads every .desktop file. `xdg_data_dirs` NULL means $XDG_DATA_DIRS
 * (or "/usr/share/"); `locale` NULL means the LC_MESSAGES locale. */
int ks_desktop_init(struct ks_desktop *d, const char *xdg_data_dirs, const char *locale);
void ks_desktop_free(struct ks_desktop *d);

/* Parses one file (_parse_desktop_file); false if it's skipped. */
bool ks_desktop_parse_file(struct ks_desktop *d, const char *path);
/* The same with the contents in memory (`path` names the file). */
bool ks_desktop_parse_text(struct ks_desktop *d, const char *path, const char *text,
                           size_t len);

/* _parse_exec(): the binary of an Exec line. malloc'd. */
char *ks_desktop_parse_exec(const char *cmd);

/* get_info_by_path(path, default_icon). Never NULL unless OOM. */
struct ks_app_info *ks_desktop_info_by_path(const struct ks_desktop *d, const char *path,
                                            const char *default_icon);
void ks_app_info_free(struct ks_app_info *i);

/* inotify on the directories: watch this fd and call
 * ks_desktop_on_inotify() when it's readable. -1 if unavailable. */
int ks_desktop_watch(struct ks_desktop *d);
void ks_desktop_on_inotify(struct ks_desktop *d);

#endif
