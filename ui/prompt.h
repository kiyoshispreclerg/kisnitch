/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The pop-up that asks what to do with a connection: port of upstream
 * ui/opensnitch/dialogs/prompt/__init__.py and res/prompt.ui in GTK 2.
 * Shows the process (name, icon and description from its .desktop file,
 * path, arguments, working directory), the destination, a countdown that
 * applies the default action, and lets the user pick the action, the
 * duration and what the rule matches (with the advanced options: also by
 * destination IP, port, user or checksum). The rule itself is built by
 * ui/prompt_rule.c.
 *
 * Copyright (C) 2018 Simone Margaritelli, 2019-2025 Gustavo Iñiguez Goia
 *               and the OpenSnitch contributors.
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: struct ks_prompt owns its widgets; the service, the desktop
 * parser and the settings are borrowed.
 */
#ifndef KS_UI_PROMPT_H
#define KS_UI_PROMPT_H

#include "ui/desktop.h"
#include "ui/service.h"

struct ks_prompt;

struct ks_prompt *ks_prompt_new(struct ks_service *svc, struct ks_desktop *desktop);
void ks_prompt_free(struct ks_prompt *p);

/* service ops->prompt */
void ks_prompt_ask(struct ks_prompt *p, struct ks_ask *ask);

/* Closing the UI: answers the question on screen with nothing. */
void ks_prompt_close(struct ks_prompt *p);

#endif
