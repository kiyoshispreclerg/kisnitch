/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A GtkTreeModel over a ks_qmodel: a list whose rows are read from the
 * database when the GtkTreeView asks for them, so a table of 100 000
 * events costs the same as one of 50. The view must use fixed-height mode
 * (otherwise it would ask for every row).
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 *
 * Memory: a GObject; it owns its ks_qmodel and borrows the sqlite handle.
 */
#ifndef KS_UI_QSTORE_H
#define KS_UI_QSTORE_H

#include <gtk/gtk.h>

#include "ui/qmodel.h"

#define KS_TYPE_QSTORE (ks_qstore_get_type())
#define KS_QSTORE(o) (G_TYPE_CHECK_INSTANCE_CAST((o), KS_TYPE_QSTORE, KsQStore))
#define KS_IS_QSTORE(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), KS_TYPE_QSTORE))

typedef struct _KsQStore KsQStore;
typedef struct _KsQStoreClass KsQStoreClass;

struct _KsQStore {
    GObject parent;
    struct ks_qmodel *q;
    int stamp;
};

struct _KsQStoreClass {
    GObjectClass parent_class;
};

GType ks_qstore_get_type(void);
KsQStore *ks_qstore_new(sqlite3 *h);
/* The model behind the store. After ks_qmodel_set_query() or _refresh(),
 * detach the store from its views (gtk_tree_view_set_model(v, NULL)),
 * and attach it again: the rows changed under them. */
struct ks_qmodel *ks_qstore_model(KsQStore *s);

#endif
