"""Virtual calls in C++ programs: which methods a call through a vtable can reach.

A C++ virtual call compiles to a load of the object's vtable pointer and an
indirect call through one slot of it (``call *0x18(%rax)`` is slot 3). The
binary alone does not say which class the object has, so this module combines
two pieces of evidence:

* the vtables themselves, read from the ELF file: every class's slot N and the
  method it holds (vtable symbols ``_ZTV…`` come from the binary's symbol table
  or its debug file; the slot contents from the data and its relocations);
* the method name written at the call site, read from the source line the call
  instruction belongs to (``shape->draw(cr)`` names ``draw``).

A target is reported when a vtable holds a method of that name in that slot.
That is an inference, labelled as one: the object could still be of a class
whose vtable is in another library, and a source line can hold several calls.
Calls with no source line, or no matching method, stay unresolved and are counted.
Nothing is run.
"""

import os
import re
import struct
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Relocation types that put an address into a vtable slot.
_RELATIVE = {62: {8}, 183: {1027}}           # x86-64 R_X86_64_RELATIVE, AArch64 R_AARCH64_RELATIVE
_ABSOLUTE = {62: {1, 6}, 183: {257, 1025}}   # R_X86_64_64 / GLOB_DAT, R_AARCH64_ABS64 / GLOB_DAT
_CALLED_NAME = re.compile(r"(?<![\w~])(~?[A-Za-z_]\w*)\s*(?:<[^()]*>)?\s*\(")
_THUNK = re.compile(r"^(?:non-virtual thunk to |virtual thunk to |covariant return thunk to )")


@dataclass
class Vtables:
    """slot -> {method short name -> {implementation symbols}}, and which classes hold them."""

    slots: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(set)))
    classes: int = 0
    pure: int = 0


def _sections(data):
    """{name: (address, offset, size)} and the machine number of an ELF64 little-endian file."""

    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None, {}
    machine = struct.unpack_from("<H", data, 18)[0]
    shoff, = struct.unpack_from("<Q", data, 40)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    if not shoff or shstrndx >= shnum:
        return machine, {}
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        name, kind, flags, address, offset, size, link, _info, _align, _entsize = struct.unpack_from(
            "<IIQQQQIIQQ", data, base
        )
        headers.append((name, kind, flags, address, offset, size, link))
    names_offset = headers[shstrndx][4]
    out = {}
    for name, kind, flags, address, offset, size, link in headers:
        end = data.find(b"\0", names_offset + name)
        out[data[names_offset + name:end].decode("ascii", "replace")] = (address, offset, size, kind, link, flags)
    return machine, out


def _dynamic_symbol_names(data, sections):
    if ".dynsym" not in sections or ".dynstr" not in sections:
        return []
    _, offset, size, *_ = sections[".dynsym"]
    _, strings, *_ = sections[".dynstr"]
    names = []
    for base in range(offset, offset + size, 24):
        name = struct.unpack_from("<I", data, base)[0]
        end = data.find(b"\0", strings + name)
        names.append(data[strings + name:end].decode("ascii", "replace"))
    return names


def slot_words(binary):
    """What the words of a binary's data hold, for reading vtables.

    Returns (word, code): word(address) gives ("address", value) or
    ("import", symbol name) or None, and code(value) says whether a value
    points into executable code. Relocations are read from RELA sections
    (an import, or a relative address); otherwise the word in the file is
    used, which covers non-PIE binaries and packed RELR relocations, whose
    addends sit in place.
    """

    data = Path(binary).read_bytes()
    machine, sections = _sections(data)
    if machine not in _RELATIVE:
        return (lambda address: None), (lambda value: False)
    relocated = {}
    dynamic = _dynamic_symbol_names(data, sections)
    for _address, offset, size, kind, _link, _flags in sections.values():
        if kind != 4:   # SHT_RELA
            continue
        for base in range(offset, offset + size - 23, 24):
            where, info, addend = struct.unpack_from("<QQq", data, base)
            kind_of, symbol = info & 0xFFFFFFFF, info >> 32
            if kind_of in _RELATIVE[machine]:
                relocated[where] = ("address", addend)
            elif kind_of in _ABSOLUTE[machine] and 0 < symbol < len(dynamic):
                relocated[where] = ("import", dynamic[symbol])
    loaded = [(address, offset, size) for address, offset, size, kind, _link, _flags in sections.values()
              if address and kind == 1]   # SHT_PROGBITS
    code_ranges = [(address, address + size) for address, _o, size, _k, _l, flags in sections.values()
                   if address and flags & 0x4]   # SHF_EXECINSTR

    def word(address):
        if address in relocated:
            return relocated[address]
        for start, offset, size in loaded:
            if start <= address <= start + size - 8:
                return "address", struct.unpack_from("<Q", data, offset + address - start)[0]
        return None

    def code(value):
        return any(start <= value < end for start, end in code_ranges)

    return word, code


def read_vtables(binary, symbols, functions, demangle=None):
    """Vtables of a C++ binary.

    symbols: (address, size, name) of the vtable objects (_ZTV…).
    functions: {address: (symbol, readable name)} of the binary's functions.
    demangle: readable names for imported symbols (a list in, a list out).
    Each vtable group is read word by word. A word pointing into code, or
    naming an imported function, is a slot; any other word (offset-to-top,
    type information, virtual base offsets) is a header, and the next slot
    starts again from zero, as in each sub-table of a multiple-inheritance
    vtable group.
    """

    word, code = slot_words(binary)
    table = Vtables()
    imported = []
    for address, size, _name in symbols:
        table.classes += 1
        slot = -1
        for at in range(address, address + size, 8):
            kind, value = word(at) or ("address", 0)
            if kind == "import" and not value.startswith("_ZTI"):
                slot += 1
                if value in ("__cxa_pure_virtual", "__cxa_deleted_virtual"):
                    table.pure += 1
                else:
                    imported.append((slot, value))
                continue
            if kind != "address" or not code(value):
                slot = -1
                continue
            slot += 1
            target = functions.get(value)
            if target is not None:
                symbol, readable = target
                table.slots[slot][method_name(readable)].add(symbol)
    if imported:
        names = (demangle or list)([symbol for _, symbol in imported])
        for (slot, symbol), readable in zip(imported, names):
            table.slots[slot][method_name(readable)].add(symbol + "@import")
    return table


def method_name(readable):
    """'non-virtual thunk to ns::Shape::draw(cairo_t*) const' -> 'draw'."""

    depth, out = 0, []
    for char in _THUNK.sub("", readable):
        if char == "<":
            depth += 1
        elif char == ">" and depth:
            depth -= 1
        elif not depth:
            out.append(char)
    name = "".join(out).split("(", 1)[0]   # after the template arguments, which may hold "(T)2"
    return name.rsplit("::", 1)[-1].strip()


def methods_at(line_text):
    """Names called in one source line: obj->m(…), obj.m(…), and m(…) inside a member function.

    Keywords and plain functions come along too; only names a vtable holds in
    the call's slot are used, so they never become targets on their own.
    """

    code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line_text.split("//", 1)[0])
    return set(_CALLED_NAME.findall(code))


_DELETE = re.compile(r"\bdelete\b")
_STATEMENT_END = (";", "{", "}")


def vtable_symbols(path):
    """(address, size, name) of the vtables (_ZTV…) in an ELF file's symbol table."""

    env = dict(os.environ, LC_ALL="C")
    try:
        result = subprocess.run(
            ["readelf", "-sW", str(path)], capture_output=True, text=True, errors="replace",
            env=env, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    found = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "OBJECT" and parts[7].startswith("_ZTV"):
            try:
                address, size = int(parts[1], 16), int(parts[2], 0)
            except ValueError:
                continue
            if address and size:
                found[address] = (address, size, parts[7])
    return sorted(found.values())


@dataclass(frozen=True)
class Site:
    caller: str      # symbol of the function the call is in
    address: int
    slot: int
    file: str | None
    line: int | None
    targets: frozenset   # implementation symbols ("…@import" for a library's)
    kind: str        # "resolved", "destructor" (delete), "unresolved", "no source"


class VirtualCalls:
    """Virtual calls of one program, resolved on demand.

    Built from the code map and the slot calls disassembly found. Sites are
    located (addr2line) and their source lines read only for the functions
    asked about, so a call graph of one function fetches one or two files.
    """

    def __init__(self, cmap, slot_calls, locate, fetch_source, demangle=None):
        self.cmap = cmap
        self.slot_calls = slot_calls
        self._locate = locate
        self._fetch = fetch_source
        self._demangle = demangle
        self._vtables = None
        self._sites = {}
        self._lines = {}

    @property
    def vtables(self):
        if self._vtables is None:
            sources = [self.cmap.debug_file, self.cmap.binary] if self.cmap.debug_file else [self.cmap.binary]
            symbols = []
            for source in sources:
                symbols = vtable_symbols(source)
                if symbols:
                    break
            functions = {f.address: (f.symbol, f.name) for f in self.cmap.functions}
            self._vtables = read_vtables(self.cmap.binary, symbols, functions, self._demangle) if symbols else Vtables()
        return self._vtables

    def _source_line(self, file, line):
        if file not in self._lines:
            path = self._fetch(self.cmap, file)
            try:
                self._lines[file] = path.read_text(errors="replace").splitlines() if path else None
            except OSError:
                self._lines[file] = None
        lines = self._lines[file]
        if not lines or not line or line > len(lines):
            return None
        return lines, line

    def _resolve(self, calls):
        todo = [call for call in calls if call[1] not in self._sites]
        if todo and self.vtables.classes and self.cmap.debug_file:
            places = self._locate(self.cmap.debug_file, [address for _, address, _ in todo])
        else:
            places = [(None, None)] * len(todo)
        for (caller, address, slot), (file, line) in zip(todo, places):
            self._sites[address] = self._site(caller, address, slot, file, line)
        return [self._sites[address] for _, address, _ in calls]

    def _site(self, caller, address, slot, file, line):
        found = self._source_line(file, line) if file else None
        if found is None:
            return Site(caller, address, slot, file, line, frozenset(), "no source")
        lines, number = found
        held = self.vtables.slots.get(slot, {})
        targets = set()
        # a call can be written over several lines; look back while the statement continues
        for index in range(number, max(0, number - 3), -1):
            for name in methods_at(lines[index - 1]):
                targets |= held.get(name, set())
            if targets or index < 2 or lines[index - 2].rstrip().endswith(_STATEMENT_END):
                break
        if targets:
            return Site(caller, address, slot, file, line, frozenset(targets), "resolved")
        if _DELETE.search(lines[number - 1]):
            return Site(caller, address, slot, file, line, frozenset(), "destructor")
        return Site(caller, address, slot, file, line, frozenset(), "unresolved")

    def from_callers(self, symbols):
        """Sites in the functions named by symbols."""

        symbols = set(symbols)
        return self._resolve([call for call in self.slot_calls if call[0] in symbols])

    def into(self, function):
        """Sites that may call function (a codemap.Function), checked by slot first, then by name."""

        name = method_name(function.name)
        slots = {slot for slot, held in self.vtables.slots.items() if function.symbol in held.get(name, ())}
        candidates = [call for call in self.slot_calls if call[2] in slots]
        return [site for site in self._resolve(candidates) if function.symbol in site.targets]
