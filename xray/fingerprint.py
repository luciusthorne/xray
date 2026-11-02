"""Which language and toolchain built an ELF binary, and what it bundles.

The binary is read, never run. Go binaries carry a build-info section
with the module and its dependencies; Rust binaries keep the rustc
version in .comment and the paths of the crates they were built from in
panic messages; C++ binaries reference libstdc++ or the C++ ABI; and
PyInstaller bundles end with a known cookie. Anything else is reported
as C or unknown, with the compiler from .comment when present.
"""

import mmap
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

_GO_MAGIC = b"\xff Go buildinf:"
_PYINSTALLER = b"MEI\x0c\x0b\x0a\x0b\x0e"
_RUST_MARKERS = (b"RUST_BACKTRACE", b"library/core/src/", b"rust_begin_unwind")
_CPP_MARKERS = (b"GLIBCXX_", b"__cxa_throw", b"libc++.so", b"libstdc++.so")
# Runtime libraries that only one language links against.
_RUNTIMES = (
    (b"libgfortran.so", "Fortran"),
    (b"libgphobos.so", "D"),
    (b"libphobos2", "D"),
    (b"libHSbase", "Haskell"),
    (b"libswiftCore.so", "Swift"),
    (b"libobjc.so", "Objective-C"),
)
_CRATE = re.compile(
    rb"registry/src/[^/\x00]+/([A-Za-z0-9_-]+?)-(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?)/"
)
_RUSTC = re.compile(rb"rustc version (\d+\.\d+\.\d+[^\x00\s]*)")
_MAX_ITEMS = 400


@dataclass(frozen=True)
class Fingerprint:
    language: str = "unknown"
    toolchain: str | None = None
    compilers: tuple = ()
    module: str | None = None
    dependencies: tuple = ()
    settings: tuple = ()
    notes: tuple = field(default_factory=tuple)


def _sections(data):
    """Return {name: bytes} for the sections of an ELF image."""

    if data[:4] != b"\x7fELF" or len(data) < 64:
        return {}

    wide = data[4] == 2
    order = "<" if data[5] == 1 else ">"

    if wide:
        shoff, = struct.unpack_from(order + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x3A)
        layout = order + "IIQQQQIIQQ"
    else:
        shoff, = struct.unpack_from(order + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x2E)
        layout = order + "IIIIIIIIII"

    if not shoff or shnum == 0 or shstrndx >= shnum:
        return {}

    headers = []
    for index in range(shnum):
        start = shoff + index * shentsize
        if start + struct.calcsize(layout) > len(data):
            return {}
        values = struct.unpack_from(layout, data, start)
        name, kind, offset, size = values[0], values[1], values[4], values[5]
        headers.append((name, kind, offset, size))

    _name, _kind, str_offset, str_size = headers[shstrndx]
    names = data[str_offset:str_offset + str_size]
    result = {}

    for name, kind, offset, size in headers:
        if kind == 8:  # SHT_NOBITS holds no file data
            continue
        end = names.find(b"\x00", name)
        label = names[name:end].decode("ascii", "replace")
        result[label] = data[offset:offset + size]

    return result


def _uvarint(data, index):
    value = shift = 0
    while index < len(data):
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7
    raise ValueError("truncated varint")


def _go_buildinfo(section):
    """Return (version, modinfo) from a Go 1.18+ build-info section."""

    if not section.startswith(_GO_MAGIC) or len(section) < 32:
        return None, None

    if not section[15] & 0x2:
        return None, None  # pre-1.18 layout stores pointers, not strings

    index = 32
    length, index = _uvarint(section, index)
    version = section[index:index + length].decode("utf-8", "replace")
    index += length
    length, index = _uvarint(section, index)
    modinfo = section[index:index + length]

    if len(modinfo) >= 33 and modinfo[-17] == 0x0A:
        modinfo = modinfo[16:-16]

    return version, modinfo.decode("utf-8", "replace")


def _go(sections, data):
    version, modinfo = _go_buildinfo(sections.get(".go.buildinfo", b""))

    if version is None:
        match = re.search(rb"go1\.\d+(?:\.\d+)?", data)
        return Fingerprint(
            "Go", match.group().decode() if match else None,
            notes=("Build info uses the pre-1.18 layout: modules not decoded",),
        )

    module = None
    dependencies = []
    settings = []

    for line in modinfo.splitlines():
        parts = line.split("\t")
        if parts[0] == "mod" and len(parts) >= 2:
            module = " ".join(part for part in parts[1:3] if part)
        elif parts[0] == "dep" and len(parts) >= 3:
            dependencies.append(f"{parts[1]} {parts[2]}")
        elif parts[0] == "=>" and len(parts) >= 3 and dependencies:
            dependencies[-1] += f" => {parts[1]} {parts[2]}"
        elif parts[0] == "build" and len(parts) >= 2:
            settings.append(parts[1])

    return Fingerprint(
        "Go", version, module=module,
        dependencies=tuple(dependencies), settings=tuple(settings),
    )


def _comment(sections):
    raw = sections.get(".comment", b"")
    return tuple(dict.fromkeys(
        item.decode("utf-8", "replace").strip()
        for item in raw.split(b"\x00") if item.strip()
    ))


def fingerprint(path):
    """Return the Fingerprint of an ELF file; non-ELF files are 'unknown'."""

    path = Path(path)

    with path.open("rb") as handle:
        try:
            data = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            return Fingerprint(notes=("Empty file",))

    with data:
        sections = _sections(data)

        if not sections and data[:4] != b"\x7fELF":
            return Fingerprint(notes=("Not an ELF binary",))

        compilers = _comment(sections)

        if ".go.buildinfo" in sections:
            return _go(sections, data)

        rustc = next(
            (m.group(1).decode() for item in compilers
             if (m := _RUSTC.search(item.encode()))),
            None,
        )

        if rustc or any(data.find(marker) != -1 for marker in _RUST_MARKERS):
            crates = {}
            for match in _CRATE.finditer(data):
                name, version = (part.decode() for part in match.groups())
                crates.setdefault(name, version)
                if len(crates) >= _MAX_ITEMS:
                    break
            notes = () if crates else (
                "No crate paths kept in this binary (paths were remapped or stripped)",
            )
            return Fingerprint(
                "Rust", f"rustc {rustc}" if rustc else None,
                compilers=tuple(c for c in compilers if "rustc" not in c),
                dependencies=tuple(f"{name} {version}" for name, version in sorted(crates.items())),
                notes=notes,
            )

        if data.rfind(_PYINSTALLER) != -1:
            return Fingerprint(
                "Python (PyInstaller bundle)", compilers=compilers,
                notes=("The bundled Python code is not extracted",),
            )

        for marker, language in _RUNTIMES:
            if data.find(marker) != -1:
                return Fingerprint(language, compilers=compilers)

        if any(data.find(marker) != -1 for marker in _CPP_MARKERS):
            return Fingerprint("C++", compilers=compilers)

        if compilers:
            return Fingerprint("C", compilers=compilers)

        if data.find(b"libc.so") != -1:
            return Fingerprint(
                "C (inferred)",
                notes=(("No compiler record (.comment was stripped); it links the C "
                       "library and no other language runtime"),),
            )

        return Fingerprint(notes=("No language markers found",))


def toolchain_lines(path, limit=60):
    """Lines for --toolchain."""

    found = fingerprint(path)
    lines = [f"Language: {found.language}"]

    if found.toolchain:
        lines.append(f"Toolchain: {found.toolchain}")

    if found.compilers:
        lines.append("Compilers:")
        lines.extend(f"- {item}" for item in found.compilers)

    if found.module:
        lines.append(f"Module: {found.module}")

    if found.dependencies:
        label = "Crates" if found.language == "Rust" else "Dependencies"
        lines.append(f"{label} ({len(found.dependencies)}):")
        lines.extend(f"- {item}" for item in found.dependencies[:limit])
        if len(found.dependencies) > limit:
            lines.append(f"- ... and {len(found.dependencies) - limit} more")

    if found.settings:
        lines.append("Build settings:")
        lines.extend(f"- {item}" for item in found.settings)

    if found.notes:
        lines.append("Notes:")
        lines.extend(f"- {item}" for item in found.notes)

    return lines
