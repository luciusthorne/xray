"""Qt signal and slot connections, read from a compiled program.

A new-style ``connect(sender, &Sender::signal, receiver, &Receiver::slot)``
compiles to a call to ``QObject::connectImpl`` with the addresses of the
signal and the slot loaded just before it. Disassembly records those
references for every connect call (disasm.DisasmResult.connects); this
module tells them apart:

* a signal is a function moc generated: its source file is a ``moc_*.cpp``
  (``mocs_compilation.cpp`` when they are compiled together, ``*.moc`` when
  a source file includes its own moc output);
* a lambda slot comes wrapped in ``QtPrivate::QCallableObject<Lambda, …>::impl``,
  whose type names the lambda;
* a function imported from another library (``QObject::destroyed``, from
  QtCore) is taken as the signal when no reference is known to be one;
* the remaining functions of the program are the slots.

Each connection is labelled inferred: the references are read from the
instructions that set up the call, not from Qt's own tables, and a
connection made at run time by name (SIGNAL()/SLOT() strings, QML) is not
seen. Nothing is run.
"""

import posixpath
import shutil
import subprocess
from dataclasses import dataclass

_WRAPPERS = ("QtPrivate::QCallableObject<", "QtPrivate::QFunctorSlotObject<", "QtPrivate::QSlotObject<",
             "QtPrivate::QStaticSlotObject<", "QtPrivate::QPrivateSlotObject<")
_MOC_PLUMBING = ("qt_static_metacall", "qt_metacall", "qt_metacast", "metaObject", "qt_check_for_QGADGET_macro")


@dataclass(frozen=True)
class Connection:
    caller: str        # symbol of the function that connects
    address: int       # the connect call
    signals: tuple     # local symbols or "name@import"
    slots: tuple
    file: str | None = None
    line: int | None = None
    function: str | None = None   # readable name of the function whose line makes the connection

    @property
    def certain(self):
        """One signal and one slot: the instructions before the call hold nothing else.

        With more, references for a neighbouring connect() (connections built
        in one list) may be mixed in, so each pairing is only a candidate.
        """

        return len(self.signals) == 1 and len(self.slots) == 1


def _first_template_argument(name):
    start = name.find("<")
    depth = 0
    for index in range(start, len(name)):
        depth += name[index] in "<({"
        depth -= name[index] in ">)}"
        if (depth == 1 and name[index] == ",") or depth == 0:
            return name[start + 1:index].strip()
    return ""


_QT_CONNECT_FRAMES = ("QObject::connect", "QObjectPrivate::connect", "QtPrivate::")


def _is_connect_machinery(function):
    head = function.split("(", 1)[0].split("<", 1)[0]
    head = head.rsplit(" ", 1)[-1]   # template functions start with their return type: "bool QObject::connect"
    return head.startswith(_QT_CONNECT_FRAMES)


def connect_lines(debug_file, addresses):
    """[(function, file, line)] of the code that called connect() at each address.

    connect() is a template inlined from Qt's headers, and the function that
    calls it may itself be inlined into another. addr2line -i -f lists the
    inlined chain innermost first; the first frame outside Qt's connect
    machinery is the line someone wrote.
    """

    tool = shutil.which("addr2line")
    if tool is None or not addresses:
        return [(None, None, None)] * len(addresses)
    try:
        result = subprocess.run(
            [tool, "-a", "-i", "-f", "-C", "-e", str(debug_file)], input="\n".join(hex(a) for a in addresses),
            capture_output=True, text=True, errors="replace", check=False, timeout=300,
        )
    except (OSError, subprocess.SubprocessError):
        return [(None, None, None)] * len(addresses)
    chains, rows = [], result.stdout.splitlines()
    index = 0
    while index < len(rows):
        if rows[index].startswith("0x"):
            chains.append([])
            index += 1
            continue
        if chains and index + 1 < len(rows):
            function, place = rows[index], rows[index + 1]
            path, _, line = place.split(" (discriminator", 1)[0].strip().rpartition(":")
            ok = path and not path.startswith("??") and line.isdigit() and int(line)
            chains[-1].append((function, posixpath.normpath(path) if ok else None, int(line) if ok else None))
        index += 2
    if len(chains) != len(addresses):
        return [(None, None, None)] * len(addresses)
    found = []
    for chain in chains:
        written = [frame for frame in chain if not _is_connect_machinery(frame[0])]
        found.append(written[0] if written else (None, None, None))   # connect() itself was not inlined
    return found


class QtConnections:
    """Signal and slot connections of one program, from its code map and disassembly."""

    def __init__(self, cmap, connects, base, demangle, locate=None):
        self.cmap = cmap
        self._base = base
        self._demangle = demangle
        self._by_symbol = {f.symbol: f for f in cmap.functions}
        self._by_base = {}
        for function in cmap.functions:
            self._by_base.setdefault(base(function.name), []).append(function)
        imports = sorted({ref for _, _, refs in connects for ref in refs if ref.endswith("@import")})
        self._import_names = dict(zip(imports, demangle([ref[: -len("@import")] for ref in imports])))
        self.connections = [
            self._connection(caller, address, [
                ref for ref in refs if not ref.endswith("@import") or "(" in self._import_names[ref]
            ])   # an imported object (QWindow::staticMetaObject) is an argument, not a signal or slot
            for caller, address, refs in connects
        ]
        if locate is not None and cmap.debug_file and self.connections:
            places = locate(cmap.debug_file, [c.address for c in self.connections])
            self.connections = [
                Connection(c.caller, c.address, c.signals, c.slots, file, line, function)
                for c, (function, file, line) in zip(self.connections, places)
            ]

    def readable(self, reference):
        if reference.endswith("@import"):
            return self._import_names.get(reference, reference)
        function = self._by_symbol.get(reference)
        return function.name if function else reference

    def is_signal(self, reference):
        if reference.endswith("@import"):
            return "QPrivateSignal" in self.readable(reference)
        function = self._by_symbol.get(reference)
        if function is None or not function.file:
            return False
        source = posixpath.basename(function.file)
        if not (source.startswith("moc_") or source.endswith(".moc") or source == "mocs_compilation.cpp"):
            return False
        return not self._base(function.name).rsplit("::", 1)[-1] in _MOC_PLUMBING

    def _lambda_slot(self, reference):
        """Symbols of the lambda a QCallableObject<Lambda, …>::impl wraps, or None when it is not one."""

        name = self.readable(reference)
        if not name.startswith(_WRAPPERS):
            return None
        functor = _first_template_argument(name)
        if "{lambda" not in functor:
            return ()   # a member-function pointer: the slot itself is another reference
        target = self._base(functor + "::operator()() const")
        # the lambda's own function, or the wrapper it was compiled into (named after the lambda)
        return tuple(f.symbol for f in self._by_base.get(target, ())) or (reference,)

    def _connection(self, caller, address, references):
        signals, slots, imported = [], [], []
        for reference in references:
            wrapped = self._lambda_slot(reference)
            if wrapped is not None:
                slots.extend(wrapped)
            elif self.is_signal(reference):
                signals.append(reference)
            elif reference.endswith("@import"):
                imported.append(reference)
            else:
                slots.append(reference)
        if signals:
            slots.extend(imported)
        else:
            signals.extend(imported)
        return Connection(caller, address, tuple(dict.fromkeys(signals)), tuple(dict.fromkeys(slots)))

    def of(self, symbols):
        """(connected slots, connected signals) of functions: [(other end, connection)] each.

        A signal's partners are its slots and any signal it is forwarded to;
        a slot's partners are the signals it is connected to.
        """

        symbols = set(symbols)
        outgoing, incoming = [], []
        for connection in self.connections:
            if symbols & set(connection.signals):
                outgoing += [(other, connection) for other in connection.slots]
                outgoing += [(other, connection) for other in connection.signals if other not in symbols]
            if symbols & set(connection.slots):
                incoming += [(other, connection) for other in connection.signals]
        return outgoing, incoming
