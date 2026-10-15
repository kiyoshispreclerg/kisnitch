#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs upstream's preferences dialog (ui/opensnitch/dialogs/preferences.py,
# 1.8.0) on the node cases of cases.jsonl, without Qt: the widgets are small
# stand-ins. Everything that decides the node's configuration is upstream's
# code: _load_node_settings(), _load_node_auth_settings(),
# _build_node_config(), _save_node_auth_config().
#
#   upstream_prefs.py <upstream ui dir> <dir with ui_pb2.py> <cases> <out>
#
# One JSON object per case ("load" or "build"). tests/diff/ks_prefs_diff.c
# does the same with ui/prefs_node.c.
import json
import os
import sys
import types

UI, PB, CASES, OUT = sys.argv[1:5]
sys.path.insert(0, PB)
sys.path.insert(0, UI)


class Sig:
    def __init__(self):
        self.cbs = []

    def connect(self, cb):
        self.cbs.append(cb)

    def emit(self, *a):
        for cb in list(self.cbs):
            cb(*a)


class pyqtSignal:
    def __init__(self, *types_):
        self.name = None

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, obj, owner):
        if obj is None:
            return self
        return obj.__dict__.setdefault("_sig_" + self.name, Sig())


def pyqtSlot(*a, **k):
    return lambda f: f


class Anything:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        return Anything()

    def __call__(self, *a, **k):
        return Anything()

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return False


class QObject:
    def __init__(self, *a, **k):
        pass


class Widget:
    def __init__(self):
        self._text = ""
        self._checked = False
        self._enabled = True
        self._value = 0

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return Anything()

    def setText(self, t):
        self._text = t

    def text(self):
        return self._text

    def setChecked(self, c):
        self._checked = bool(c)

    def isChecked(self):
        return self._checked

    def setEnabled(self, e):
        self._enabled = bool(e)

    def isEnabled(self):
        return self._enabled

    def setValue(self, v):
        if not isinstance(v, int) or isinstance(v, bool):
            raise TypeError("setValue(self, int): argument 1 has unexpected type")
        self._value = v

    def value(self):
        return self._value

    def blockSignals(self, b):
        pass


class Combo(Widget):
    def __init__(self, texts=(), data=(), editable=False):
        super().__init__()
        self.items = [[t, d] for t, d in itertools_zip_longest(texts, data)]
        self.cur = 0 if self.items else -1
        self.edit = self.items[0][0] if self.items else ""
        self.editable = editable

    def setCurrentIndex(self, i):
        self.cur = i if 0 <= i < len(self.items) else -1
        if not self.editable:
            return
        self.edit = self.items[self.cur][0] if self.cur >= 0 else ""

    def currentIndex(self):
        return self.cur

    def setCurrentText(self, t):
        if not isinstance(t, str):
            raise TypeError("setCurrentText(self, str): argument 1 has unexpected type")
        if self.editable:
            self.edit = t
        for i, it in enumerate(self.items):
            if it[0] == t:
                self.cur = i
                return

    def currentText(self):
        if self.editable:
            return self.edit
        return self.items[self.cur][0] if self.cur >= 0 else ""

    def findData(self, d):
        for i, it in enumerate(self.items):
            if it[1] == d:
                return i
        return -1

    def itemData(self, i):
        return self.items[i][1] if 0 <= i < len(self.items) else None

    def setItemData(self, i, d):
        self.items[i][1] = d

    def clear(self):
        self.items = []
        self.cur = -1


def itertools_zip_longest(a, b):
    import itertools
    return itertools.zip_longest(a, b)


class QDialog:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return Anything()


class Ui:
    pass


def module(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


QtCore = module("PyQt6.QtCore", QObject=QObject, pyqtSignal=pyqtSignal, pyqtSlot=pyqtSlot,
                QSettings=Anything, QByteArray=bytes, QSize=Anything, Qt=Anything(),
                QEvent=Anything(), QCoreApplication=types.SimpleNamespace(
                    translate=lambda ctx, s, *a: s))
QtGui = module("PyQt6.QtGui", QTextCursor=Anything(), QCursor=Anything(), QIcon=Anything,
               QPixmap=Anything, QValidator=Anything, QDesktopServices=Anything(),
               QDoubleValidator=Anything, QIntValidator=Anything)
QtWidgets = module("PyQt6.QtWidgets", QDialog=QDialog, QMenu=Anything, QWidget=QObject,
                   QMessageBox=Anything(), QDialogButtonBox=Anything(), QApplication=Anything(),
                   QFileDialog=Anything())
uic = module("PyQt6.uic", loadUiType=lambda path: (Ui, object))
module("PyQt6", QtCore=QtCore, QtGui=QtGui, QtWidgets=QtWidgets, uic=uic)


class Database:
    DB_TYPE_MEMORY = 0
    DB_IN_MEMORY = "file::memory:"
    DB_JRNL_WAL = False
    _inst = None

    @staticmethod
    def instance():
        if Database._inst is None:
            Database._inst = Database()
        return Database._inst

    def __getattr__(self, name):
        return lambda *a, **k: True


real = os.path.join(UI, "opensnitch")
module("opensnitch.database", Database=Database, __path__=[os.path.join(real, "database")])


class Icons:
    @staticmethod
    def new(widget, name):
        return Anything()


module("opensnitch.utils", Icons=Icons, Message=Anything(), QuickHelp=Anything(),
       languages=Anything(), Versions=Anything(), FileDialog=Anything(),
       NetworkInterfaces=Anything(), qvalidator=Anything(), __path__=[os.path.join(real, "utils")])
module("opensnitch.utils.xdg", Autostart=Anything)
module("opensnitch.utils.themes", Themes=Anything)
module("opensnitch.notifications", DesktopNotifications=Anything)


class Nodes:
    configs = {}

    @staticmethod
    def instance():
        return Nodes()

    def get_node_config(self, addr):
        return Nodes.configs.get(addr)


module("opensnitch.nodes", Nodes=Nodes)

import ui_pb2  # noqa: E402

module("opensnitch.proto", import_=lambda: (ui_pb2, None))

_stdout = sys.stdout
sys.stdout = sys.stderr
from opensnitch.config import Config  # noqa: E402
from opensnitch import auth  # noqa: E402
from opensnitch.dialogs.preferences import PreferencesDialog  # noqa: E402
sys.stdout = _stdout

ADDR = "unix:/local"
LOG_LEVELS = ["DEBUG", "INFO", "IMPORTANT", "WARNING", "ERROR", "FATAL"]
TEXT_WIDGETS = ["lineNodeCACertFile", "lineNodeServerCertFile", "lineNodeCertFile",
                "lineNodeCertKeyFile", "lineNodeRulesPath", "lineNodeFwMonInterval",
                "lineNodeMaxEvents", "lineNodeMaxStats", "labelNodeVersion", "labelNodeName"]
CHECK_WIDGETS = ["checkInterceptUnknown", "checkNodeLogUTC", "checkNodeLogMicro",
                 "checkNodeAuthSkipVerify", "enableChecksums", "checkNodeFlushConns",
                 "checkNodeBypassQueue"]


def new_dialog():
    d = PreferencesDialog.__new__(PreferencesDialog)
    for n in TEXT_WIDGETS:
        setattr(d, n, Widget())
    d.lineNodeMaxEvents.setText("250")
    d.lineNodeMaxStats.setText("50")
    for n in CHECK_WIDGETS:
        setattr(d, n, Widget())
    d.spinNodeGC = Widget()
    d.spinNodeGC.setValue(100)
    d.comboNodeAction = Combo(["deny", "allow", "reject"])
    d.comboNodeMonitorMethod = Combo(["proc", "ebpf", "audit"])
    d.comboNodeLogLevel = Combo(LOG_LEVELS)
    d.comboNodeAddress = Combo(["unix:///tmp/osui.sock"], editable=True)
    d.comboNodeLogFile = Combo(["/var/log/opensnitchd.log", "/dev/stdout"], editable=True)
    d.comboNodeAuthType = Combo(["Simple", "Simple TLS", "Mutual TLS"],
                                [auth.Simple, auth.TLSSimple, auth.TLSMutual])
    d.comboNodeAuthVerifyType = Combo(
        ["no-client-cert", "req-cert", "req-any-cert", "verify-cert", "req-and-verify-cert"],
        [auth.NO_CLIENT_CERT, auth.REQ_CERT, auth.REQ_ANY_CERT, auth.VERIFY_CERT,
         auth.REQ_AND_VERIFY_CERT])
    d.comboNodes = Combo([ADDR + " - host"], [ADDR])
    d.statusLabel = Widget()
    d._node_needs_update = False
    d._node_list = {}
    d._nodes = Nodes()
    return d


def dump(d):
    f = {n: getattr(d, n).text() for n in TEXT_WIDGETS}
    for n in CHECK_WIDGETS:
        f[n] = getattr(d, n).isChecked()
    f["spinNodeGC"] = d.spinNodeGC.value()
    for n in ("comboNodeAction", "comboNodeMonitorMethod", "comboNodeLogLevel",
              "comboNodeAuthType", "comboNodeAuthVerifyType"):
        f[n] = getattr(d, n).currentIndex()
    for n in ("comboNodeAddress", "comboNodeLogFile"):
        f[n] = getattr(d, n).currentText()
        f[n + "_enabled"] = getattr(d, n).isEnabled()
    for n in ("lineNodeCACertFile", "lineNodeServerCertFile", "lineNodeCertFile",
              "lineNodeCertKeyFile", "checkNodeAuthSkipVerify", "comboNodeAuthVerifyType"):
        f[n + "_enabled"] = getattr(d, n).isEnabled()
    f["needs_update"] = d._node_needs_update
    return f


FIELDS = {"version": "labelNodeVersion", "name": "labelNodeName"}


def fill(d, form):
    for k, v in form.items():
        w = getattr(d, k)
        if isinstance(w, Combo):
            if w.editable and isinstance(v, str):
                w.setCurrentText(v)
            else:
                w.setCurrentIndex(v)
        elif k == "spinNodeGC":
            w.setValue(v)
        elif k in CHECK_WIDGETS:
            w.setChecked(v)
        else:
            w.setText(v)


def normalize(status):
    """The text of an exception depends on PyQt and on the Python version: compare its kind."""
    prefix = "Error loading config %s: " % ADDR
    if not status.startswith(prefix):
        return status
    msg = status[len(prefix):]
    if msg.startswith(("setCurrentText", "setValue", "int() argument", "'int' object",
                       "'NoneType'", "object is not subscriptable", "'bool' object",
                       "'str' object", "'float' object", "'list' object")):
        return prefix + "TypeError"
    if msg.startswith("invalid literal"):
        return prefix + "ValueError"
    return status


def run(case):
    d = new_dialog()
    if case["kind"] == "load":
        data = types.SimpleNamespace(version=case["version"], name=case["name"],
                                     logLevel=case["loglevel"], config=case["config"])
        d._node_list = {ADDR: {"data": data}}
        d._load_node_settings()
        return {"id": case["id"], "form": dump(d), "status": normalize(d.statusLabel.text()),
                "config": data.config}
    if case["kind"] == "build":
        fill(d, case["form"])
        Nodes.configs = {ADDR: case["config"]} if case["config"] is not None else {}
        out, err = d._build_node_config(ADDR)
        return {"id": case["id"], "out": out, "error": err, "form": dump(d)}
    raise SystemExit("unknown case kind")


def main():
    with open(CASES) as f, open(OUT, "w") as out:
        for line in f:
            if line.strip():
                out.write(json.dumps(run(json.loads(line)), sort_keys=True) + "\n")


main()
