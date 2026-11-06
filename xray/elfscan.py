import os
import re
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
    )
