import json
import os
import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from xray.entrypoints import command_kind

_NEEDED = re.compile(r"\(NEEDED\)\s+Shared library: \[(.+?)\]")
_RPATH = re.compile(r"\(RPATH\)\s+Library rpath: \[(.*?)\]")
_RUNPATH = re.compile(r"\(RUNPATH\)\s+Library runpath: \[(.*?)\]")
_NODEFLIB = re.compile(r"\(FLAGS_1\)\s+Flags:.*\bNODEFLIB\b")
_SYMBOL = re.compile(
    r"^\s*\d+:\s+\S+\s+\S+\s+(\w+)\s+(\w+)\s+\w+\s+(\S+)\s*(\S*)"
)
_INTERP = re.compile(r"^\s*\[\s*\d+\]\s+(.+?)\s*$", re.MULTILINE)

_DEFINED_TYPES = {"FUNC", "OBJECT", "IFUNC"}


@dataclass(frozen=True)
class ElfScan:
    """What an ELF binary needs, imports and provides.

    needed lists the shared libraries it links against, interpreter is
    the dynamic loader path (None for static binaries), imports the
    symbols it expects from libraries, and exports the symbols it
    defines. All tuples are sorted and unique, and symbol names have
    their version suffix (@GLIBC_2.2.5) removed.

    This reads the dynamic symbol table through readelf. It does not
    disassemble code, so it shows what a binary links to, not what its
    functions do.
    """

    needed: tuple = ()
    interpreter: str | None = None
    imports: tuple = ()
    exports: tuple = ()
    rpath: tuple = ()
    runpath: tuple = ()
    elf_class: int = 64
    nodeflib: bool = False
    dlopen: tuple = ()  # DlopenEntry: libraries loaded on demand (FDO dlopen metadata notes)


@dataclass(frozen=True)
class DlopenEntry:
    """One entry of an FDO dlopen metadata note (.note.dlopen).

    The program may load one of sonames (tried in order) when the feature is
    used. Spec: https://uapi-group.org/specifications/specs/elf_dlopen_metadata/
    """

    feature: str
    priority: str
    sonames: tuple
    description: str = ""


NT_FDO_DLOPEN_METADATA = 0x407C0C0A
_MAX_NOTE_BYTES = 1 << 20


def parse_note_section(data, little=True, align=4):
    """Yield (name, type, desc) for each note in a SHT_NOTE section's bytes."""

    order = "<" if little else ">"
    align = 8 if align == 8 else 4
    pad = lambda size: (size + align - 1) & ~(align - 1)
    offset = 0
    while offset + 12 <= len(data):
        namesz, descsz, kind = struct.unpack_from(order + "III", data, offset)
        offset += 12
        name = data[offset:offset + namesz].rstrip(b"\0").decode("ascii", "replace")
        offset += pad(namesz)
        if offset + descsz > len(data):
            return
        yield name, kind, data[offset:offset + descsz]
        offset += pad(descsz)


def parse_dlopen_payload(desc):
    """DlopenEntry tuple from one note's JSON payload; malformed entries are skipped."""

    try:
        items = json.loads(desc.rstrip(b"\0").decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return ()
    if not isinstance(items, list):
        return ()
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        sonames = item.get("soname")
        if not isinstance(sonames, list) or not sonames or not all(isinstance(s, str) and s for s in sonames):
            continue
        priority = item.get("priority", "recommended")
        out.append(DlopenEntry(
            str(item.get("feature", "")), priority if isinstance(priority, str) else "recommended",
            tuple(sonames), str(item.get("description", "")),
        ))
    return tuple(out)


def read_dlopen_notes(path):
    """Libraries an ELF file declares it may dlopen, from FDO dlopen metadata notes."""

    try:
        with open(path, "rb") as handle:
            ident = handle.read(64)
            if len(ident) < 52 or ident[:4] != b"\x7fELF":
                return ()
            is64, little = ident[4] == 2, ident[5] == 1
            order = "<" if little else ">"
            if is64:
                shoff, = struct.unpack_from(order + "Q", ident, 0x28)
                shentsize, shnum = struct.unpack_from(order + "HH", ident, 0x3A)
                layout, width = order + "IIQQQQIIQQ", 64
            else:
                shoff, = struct.unpack_from(order + "I", ident, 0x20)
                shentsize, shnum = struct.unpack_from(order + "HH", ident, 0x2E)
                layout, width = order + "IIIIIIIIII", 40
            if not shoff or shentsize < width or not 0 < shnum < 65280:
                return ()
            handle.seek(shoff)
            table = handle.read(shentsize * shnum)
            entries = []
            for index in range(shnum):
                if (index + 1) * shentsize > len(table):
                    break
                fields = struct.unpack_from(layout, table, index * shentsize)
                # same field order in both classes: name, type, flags, addr, offset, size, link, info, addralign
                sh_type, sh_offset, sh_size, sh_align = fields[1], fields[4], fields[5], fields[8]
                if sh_type != 7 or not 0 < sh_size <= _MAX_NOTE_BYTES:
                    continue
                handle.seek(sh_offset)
                data = handle.read(sh_size)
                for name, kind, desc in parse_note_section(data, little, sh_align):
                    if name == "FDO" and kind == NT_FDO_DLOPEN_METADATA:
                        entries.extend(parse_dlopen_payload(desc))
            return tuple(entries)
    except (OSError, struct.error):
        return ()


def parse_dynamic(text):
    """Return the shared libraries listed by readelf -d."""

    return tuple(sorted(set(_NEEDED.findall(text))))


def parse_search_paths(text):
    """Return (rpath, runpath, nodeflib) from readelf -d output.

    Each path list keeps its entries in order, including empty entries,
    which the loader reads as the current directory.
    """

    def entries(pattern):
        match = pattern.search(text)
        return tuple(match.group(1).split(":")) if match else ()

    return entries(_RPATH), entries(_RUNPATH), _NODEFLIB.search(text) is not None


def elf_class(path):
    """Return 32 or 64 from the ELF identification bytes (64 if unreadable)."""

    try:
        with open(path, "rb") as handle:
            ident = handle.read(5)
    except OSError:
        return 64
    return 32 if len(ident) == 5 and ident[4] == 1 else 64


def parse_symbols(text):
    """Return (imports, exports) from readelf --dyn-syms -W output."""

    imports = set()
    exports = set()

    for line in text.splitlines():
        match = _SYMBOL.match(line)

        if not match:
            continue

        kind, bind, index, raw = match.groups()
        name = raw.split("@", 1)[0]

        if not name:
            continue

        if index == "UND":
            imports.add(name)
        elif bind in ("GLOBAL", "WEAK") and kind in _DEFINED_TYPES:
            exports.add(name)

    return tuple(sorted(imports)), tuple(sorted(exports))


def parse_interp(text):
    """Return the interpreter path from readelf -p .interp, or None."""

    match = _INTERP.search(text)

    return match.group(1) if match else None


def _readelf(*args):
    env = dict(os.environ)
    env["LC_ALL"] = "C"

    result = subprocess.run(
        ["readelf", *args],
        capture_output=True,
        text=True,
        errors="replace",
        env=env,
        check=False,
    )

    return result.stdout


def scan_elf(path):
    """Return an ElfScan for an ELF file.

    Anything that is not an ELF file, or any failure to run readelf,
    gives an empty ElfScan.
    """

    path = Path(path)

    if command_kind(path) != "elf":
        return ElfScan()

    try:
        dynamic = _readelf("-d", "-W", str(path))
        symbols = _readelf("--dyn-syms", "-W", str(path))
        interp = _readelf("-p", ".interp", str(path))
    except OSError:
        return ElfScan()

    imports, exports = parse_symbols(symbols)
    rpath, runpath, nodeflib = parse_search_paths(dynamic)

    return ElfScan(
        parse_dynamic(dynamic),
        parse_interp(interp),
        imports,
        exports,
        rpath,
        runpath,
        elf_class(path),
        nodeflib,
        read_dlopen_notes(path),
    )
