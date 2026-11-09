"""Qt signal-slot connections read from connect() calls in a compiled program."""

import shutil
import subprocess
from types import SimpleNamespace

import pytest

from xray import codemap
from xray.disasm import parse_calls
from xray.qtsignals import QtConnections, _is_connect_machinery


def function(name, symbol, file):
    return SimpleNamespace(name=name, symbol=symbol, file=file, line=1, address=0, size=0)


FUNCTIONS = [
    function("Button::clicked()", "sig", "/build/moc_button.cpp"),
    function("Button::qt_static_metacall(QObject*, QMetaObject::Call, int, void**)", "meta", "/build/moc_button.cpp"),
    function("Window::onClicked()", "slot", "/src/window.cpp"),
    function("Window::Window()::{lambda()#1}::operator()() const", "lam", "/src/window.cpp"),
    function("QtPrivate::QCallableObject<Window::Window()::{lambda()#1}, QtPrivate::List<>, void>::impl(int, "
             "QtPrivate::QSlotObjectBase*, QObject*, void**, bool*)", "wrap", "/usr/include/qt6/QtCore/qobject.h"),
    function("Window::Window()", "ctor", "/src/window.cpp"),
]
CMAP = SimpleNamespace(functions=FUNCTIONS, debug_file=None)


def demangle(symbols):
    names = {"_ZN7QObject9destroyedEPS_": "QObject::destroyed(QObject*)",
             "_ZN7QWindow16staticMetaObjectE": "QWindow::staticMetaObject"}
    return [names.get(symbol, symbol) for symbol in symbols]


def connections(*refs):
    return QtConnections(CMAP, [("ctor", 0x10, ref) for ref in refs], codemap._base, demangle).connections


def test_signals_come_from_moc_and_slots_from_the_program():
    (made,) = connections(("slot", "sig"))
    assert made.signals == ("sig",) and made.slots == ("slot",) and made.certain


def test_a_lambda_slot_is_named_by_its_wrapper():
    (made,) = connections(("sig", "wrap"))
    assert made.slots == ("lam",)


def test_an_imported_function_is_the_signal_when_nothing_else_is():
    (made,) = connections(("_ZN7QObject9destroyedEPS_@import", "slot"))
    assert made.signals == ("_ZN7QObject9destroyedEPS_@import",) and made.slots == ("slot",)


def test_imported_objects_and_moc_plumbing_are_not_signals():
    (made,) = connections(("_ZN7QWindow16staticMetaObjectE@import", "meta", "sig", "slot"))
    assert made.signals == ("sig",) and made.slots == ("meta", "slot")
    assert not made.certain


def test_connect_machinery_frames_are_skipped():
    assert _is_connect_machinery("QMetaObject::Connection QObject::connect<void (QAbstractItemView::*)()>(x)")
    assert _is_connect_machinery("bool QObjectPrivate::connect<int>(int)")
    assert not _is_connect_machinery("QListWidgetPrivate::setup()")


CONNECT = (
    "0000000000001000 <ctor>:",
    "    1000:\tlea    0x100(%rip),%rax        # 1200 <slot>",
    "    1007:\tmov    0x200(%rip),%rdx        # 5000 <_ZN7QObject9destroyedEPS_@Qt_6>",
    "    100e:\tlea    0x10(%rip),%rcx        # 1300 <data+0x8>",
    "    1015:\tcall   *0x300(%rip)        # 5008 <_ZN7QObject11connectImplEPKS_PPvS1_S3_PN9QtPrivate15Q@Qt_6>",
    "    101b:\tlea    0x100(%rip),%rax        # 1200 <slot>",
    "    1022:\tcall   *0x300(%rip)        # 5008 <_ZN7QObject11connectImplEPKS_PPvS1_S3_PN9QtPrivate15Q@Qt_6>",
)


def test_connect_calls_record_the_functions_set_up_before_them():
    table = [(0x1000, 0x100, "ctor"), (0x1200, 0x10, "slot")]
    result = parse_calls("\n".join(CONNECT), table, got=[(0x5000, 0x5100)])

    assert result.connects == (
        ("ctor", 0x1015, ("slot", "_ZN7QObject9destroyedEPS_@import")),
        ("ctor", 0x1022, ("slot",)),
    )


PROGRAM = r"""#include <QObject>
#include <QCoreApplication>
#include <cstdio>

class Sender : public QObject {
    Q_OBJECT
signals:
    void ping(int value);
};

class Receiver : public QObject {
    Q_OBJECT
public slots:
    void pong(int value) { std::printf("%d\n", value); }
};

__attribute__((noinline)) void wire(Sender *sender, Receiver *receiver) {
    QObject::connect(sender, &Sender::ping, receiver, &Receiver::pong);
    QObject::connect(sender, &Sender::ping, [](int value) { std::printf("lambda %d\n", value); });
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    Sender sender;
    Receiver receiver;
    wire(&sender, &receiver);
    emit sender.ping(argc);
    return 0;
}

#include "program.moc"
"""


def _qt_flags():
    if not all(shutil.which(tool) for tool in ("c++", "pkg-config", "addr2line", "c++filt", "readelf", "objdump")):
        return None
    # Qt 6's moc: /usr/bin/moc may be Qt 5's, whose output does not build against Qt 6
    moc = next((path for path in ("/usr/lib/qt6/moc", "/usr/lib/qt6/libexec/moc", "/usr/libexec/qt6/moc")
                if shutil.which(path)), None)
    found = subprocess.run(["pkg-config", "--cflags", "--libs", "Qt6Core"], capture_output=True, text=True,
                           check=False)
    return (moc, found.stdout.split()) if moc and found.returncode == 0 else None


@pytest.mark.skipif(_qt_flags() is None, reason="needs Qt 6 development files, moc, a C++ compiler and binutils")
def test_connections_of_a_local_qt_program(tmp_path):
    moc, flags = _qt_flags()
    source = tmp_path / "program.cpp"
    source.write_text(PROGRAM)
    subprocess.run([moc, str(source), "-o", str(tmp_path / "program.moc")], check=True)
    binary = tmp_path / "program"
    subprocess.run(["c++", "-g", "-O1", "-fPIC", "-I", str(tmp_path), "-o", str(binary), str(source), *flags],
                   check=True)
    codemap._CACHE.clear()

    text = "\n".join(codemap.elf_callgraph(binary, "Sender::ping"))
    assert "connected to (Qt, 2):" in text
    assert "⇝ Receiver::pong" in text and "connected in wire, " in text
    assert "⇝ wire::{lambda#1}" in text

    back = "\n".join(codemap.elf_callgraph(binary, "Receiver::pong"))
    assert "⇜ Sender::ping" in back
