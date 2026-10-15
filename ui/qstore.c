/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See qstore.h.
 *
 * Copyright (C) 2026 the Kisnitch contributors.
 */
#include "ui/qstore.h"

static void tree_model_init(GtkTreeModelIface *iface);

G_DEFINE_TYPE_WITH_CODE(KsQStore, ks_qstore, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(GTK_TYPE_TREE_MODEL, tree_model_init))

static void ks_qstore_finalize(GObject *o)
{
    KsQStore *s = KS_QSTORE(o);
    ks_qmodel_free(s->q);
    s->q = NULL;
    G_OBJECT_CLASS(ks_qstore_parent_class)->finalize(o);
}

static void ks_qstore_class_init(KsQStoreClass *k)
{
    G_OBJECT_CLASS(k)->finalize = ks_qstore_finalize;
}

static void ks_qstore_init(KsQStore *s)
{
    s->stamp = g_random_int();
}

KsQStore *ks_qstore_new(sqlite3 *h)
{
    KsQStore *s = g_object_new(KS_TYPE_QSTORE, NULL);
    s->q = ks_qmodel_new(h);
    return s;
}

struct ks_qmodel *ks_qstore_model(KsQStore *s)
{
    return s->q;
}

/* iter->user_data holds row + 1, so that row 0 is not NULL */
static gint64 iter_row(const GtkTreeIter *it)
{
    return (gint64)(gintptr)it->user_data - 1;
}

static void set_iter(KsQStore *s, GtkTreeIter *it, gint64 row)
{
    it->stamp = s->stamp;
    it->user_data = (gpointer)(gintptr)(row + 1);
    it->user_data2 = NULL;
    it->user_data3 = NULL;
}

static GtkTreeModelFlags m_get_flags(GtkTreeModel *m)
{
    (void)m;
    return GTK_TREE_MODEL_LIST_ONLY | GTK_TREE_MODEL_ITERS_PERSIST;
}

static gint m_get_n_columns(GtkTreeModel *m)
{
    return ks_qmodel_cols(KS_QSTORE(m)->q);
}

static GType m_get_column_type(GtkTreeModel *m, gint col)
{
    (void)m;
    (void)col;
    return G_TYPE_STRING;
}

static gboolean m_get_iter(GtkTreeModel *m, GtkTreeIter *it, GtkTreePath *p)
{
    KsQStore *s = KS_QSTORE(m);
    if (gtk_tree_path_get_depth(p) != 1)
        return FALSE;
    gint i = gtk_tree_path_get_indices(p)[0];
    if (i < 0 || i >= ks_qmodel_rows(s->q))
        return FALSE;
    set_iter(s, it, i);
    return TRUE;
}

static GtkTreePath *m_get_path(GtkTreeModel *m, GtkTreeIter *it)
{
    (void)m;
    GtkTreePath *p = gtk_tree_path_new();
    gtk_tree_path_append_index(p, (gint)iter_row(it));
    return p;
}

static void m_get_value(GtkTreeModel *m, GtkTreeIter *it, gint col, GValue *v)
{
    KsQStore *s = KS_QSTORE(m);
    g_value_init(v, G_TYPE_STRING);
    g_value_set_string(v, ks_qmodel_cell(s->q, iter_row(it), col));
}

static gboolean m_iter_next(GtkTreeModel *m, GtkTreeIter *it)
{
    KsQStore *s = KS_QSTORE(m);
    gint64 r = iter_row(it) + 1;
    if (r >= ks_qmodel_rows(s->q))
        return FALSE;
    set_iter(s, it, r);
    return TRUE;
}

static gboolean m_iter_children(GtkTreeModel *m, GtkTreeIter *it, GtkTreeIter *parent)
{
    KsQStore *s = KS_QSTORE(m);
    if (parent != NULL || ks_qmodel_rows(s->q) == 0)
        return FALSE;
    set_iter(s, it, 0);
    return TRUE;
}

static gboolean m_iter_has_child(GtkTreeModel *m, GtkTreeIter *it)
{
    (void)m;
    (void)it;
    return FALSE;
}

static gint m_iter_n_children(GtkTreeModel *m, GtkTreeIter *it)
{
    if (it != NULL)
        return 0;
    gint64 n = ks_qmodel_rows(KS_QSTORE(m)->q);
    return n > G_MAXINT ? G_MAXINT : (gint)n;
}

static gboolean m_iter_nth_child(GtkTreeModel *m, GtkTreeIter *it, GtkTreeIter *parent, gint n)
{
    KsQStore *s = KS_QSTORE(m);
    if (parent != NULL || n < 0 || n >= ks_qmodel_rows(s->q))
        return FALSE;
    set_iter(s, it, n);
    return TRUE;
}

static gboolean m_iter_parent(GtkTreeModel *m, GtkTreeIter *it, GtkTreeIter *child)
{
    (void)m;
    (void)it;
    (void)child;
    return FALSE;
}

static void tree_model_init(GtkTreeModelIface *iface)
{
    iface->get_flags = m_get_flags;
    iface->get_n_columns = m_get_n_columns;
    iface->get_column_type = m_get_column_type;
    iface->get_iter = m_get_iter;
    iface->get_path = m_get_path;
    iface->get_value = m_get_value;
    iface->iter_next = m_iter_next;
    iface->iter_children = m_iter_children;
    iface->iter_has_child = m_iter_has_child;
    iface->iter_n_children = m_iter_n_children;
    iface->iter_nth_child = m_iter_nth_child;
    iface->iter_parent = m_iter_parent;
}
