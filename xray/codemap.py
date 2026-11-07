"""Code map of a compiled program: its functions, the source files they come
from, and the code itself, for every language that leaves DWARF line
information (C, C++, Rust, and others built with GCC or LLVM).

The map comes from the binary's function table (its own, or the debug file a
debuginfod server provides for its build ID), located with one batched
``addr2line`` call and demangled with binutils (C++ and both Rust manglings).
Source files are read from the paths DWARF names when they exist on this
machine, otherwise fetched from debuginfod. Nothing is built or run.
"""

import posixpath
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from xray.entrypoints import command_kind
from xray.minidebug import read_function_table

SOURCE_SUFFIXES = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++", ".inl", ".tcc",
    ".rs", ".go", ".zig", ".d", ".f", ".f90", ".m", ".mm", ".s", ".S", ".swift", ".nim", ".hs",
)

_RUST_STD = re.compile(r"/rustc(?:-[\d.]+-src|/[0-9a-f]{40})/(?:library|src)/")
_RUST_VENDOR = re.compile(r"/rustc(?:-[\d.]+-src|/[0-9a-f]{40})/vendor/(?P<crate>[A-Za-z0-9_.-]+?)-(?P<version>\d[^/]*)/")
_CARGO_CRATE = re.compile(r"/\.cargo/registry/src/[^/]+/(?P<crate>[A-Za-z0-9_.-]+?)-(?P<version>\d[^/]*)/")
_CARGO_GIT = re.compile(r"/\.cargo/git/checkouts/(?P<crate>[A-Za-z0-9_.-]+?)-[0-9a-f]{6,}/[0-9a-f]+/")
_LEGACY_RUST_HASH = re.compile(r"::h[0-9a-f]{16}$")
_RUST_DISAMBIGUATOR = re.compile(r"\[[0-9a-f]{1,16}\]")


@dataclass(frozen=True)
class Function:
    name: str          # demangled, as a reader would write it
    symbol: str        # the name in the symbol table
    address: int
    size: int
    file: str | None   # normalised DWARF path, or None when not located
    line: int | None


@dataclass
class CodeMap:
    binary: Path
    functions: list
    via: str                       # where the names and lines came from
    build_id: str | None = None
    debug_file: Path | None = None
    files: dict = field(default_factory=dict)   # file -> [Function], in line order

    def located(self):
        return [function for function in self.functions if function.file]


# -- building the map -------------------------------------------------------

def _demangle(symbols):
    """Readable names for symbols, in order, through binutils c++filt."""

    if not symbols or shutil.which("c++filt") is None:
        return list(symbols)
    try:
        result = subprocess.run(
            ["c++filt"], input="\n".join(symbols), capture_output=True, text=True,
            errors="replace", check=False, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return list(symbols)
    names = result.stdout.splitlines()
    if len(names) != len(symbols):
        return list(symbols)
    return [_RUST_DISAMBIGUATOR.sub("", _LEGACY_RUST_HASH.sub("", name)) for name in names]


def _locate(debug_file, addresses):
    """[(file, line)] for addresses, with one addr2line run (binutils is ~80x faster than eu-addr2line here)."""

    tool = shutil.which("addr2line")
    if tool is None or not addresses:
        return [(None, None)] * len(addresses)
    try:
        result = subprocess.run(
            [tool, "-e", str(debug_file)], input="\n".join(hex(a) for a in addresses),
            capture_output=True, text=True, errors="replace", check=False, timeout=300,
        )
    except (OSError, subprocess.SubprocessError):
        return [(None, None)] * len(addresses)
    rows = result.stdout.splitlines()
    if len(rows) != len(addresses):
        return [(None, None)] * len(addresses)
    out = []
    for row in rows:
        row = row.split(" (discriminator", 1)[0].strip()
        path, _, line = row.rpartition(":")
        if not path or path.startswith("??") or not line.isdigit() or int(line) == 0:
            out.append((None, None))
        else:
            out.append((posixpath.normpath(path), int(line)))
    return out


def _has_line_info(path):
    try:
        result = subprocess.run(
            ["readelf", "-SW", str(path)], capture_output=True, text=True, errors="replace",
            check=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return ".debug_line" in result.stdout


_CACHE = {}


def code_map(path, online=True):
    """CodeMap for an ELF binary, or None when it has no function names anywhere."""

    path = Path(path)
    if command_kind(path) != "elf":
        return None
    key = (str(path.resolve()), online)
    if key in _CACHE:
        return _CACHE[key]

    table, debug_file, via, build_id = read_function_table(path), None, "the binary's symbol table", None
    if table and _has_line_info(path):
        debug_file = path
    elif online:
        from xray import debuginfod

        remote = debuginfod.debug_file_and_table(path)
        if remote is not None:
            build_id, debug_file, remote_table = remote
            if remote_table:
                table, via = remote_table, "debuginfod (debug file for this build)"
            elif not table:
                table = ()
    if not table:
        _CACHE[key] = None
        return None

    rows = sorted({(address, size, symbol) for address, size, symbol in table})
    names = _demangle([symbol for _, _, symbol in rows])
    places = _locate(debug_file, [address for address, _, _ in rows]) if debug_file else [(None, None)] * len(rows)
    functions = [
        Function(name, symbol, address, size, file, line)
        for (address, size, symbol), name, (file, line) in zip(rows, names, places)
    ]
    files = defaultdict(list)
    for function in functions:
        if function.file:
            files[function.file].append(function)
    for listed in files.values():
        listed.sort(key=lambda function: (function.line or 0, function.name))
    result = CodeMap(path, functions, via, build_id, debug_file, dict(files))
    _CACHE[key] = result
    return result


# -- where a file comes from -------------------------------------------------

def origin(file):
    """(group, label) for a source path: program, dependency, standard library or system headers."""

    if _RUST_STD.search(file) or _RUST_VENDOR.search(file):
        return "standard library", "Rust standard library"
    for pattern in (_CARGO_CRATE, _CARGO_GIT):
        match = pattern.search(file)
        if match:
            version = match.groupdict().get("version")
            return "dependency", f"{match['crate']} {version}" if version else match["crate"]
    if "/include/c++/" in file or "/libstdc++" in file:
        return "standard library", "C++ standard library"
    if file.startswith(("/usr/include/", "/usr/lib/gcc/", "/usr/lib/clang/")):
        return "system headers", "system headers"
    return "program", None


def _short(file, prefix):
    for pattern in (_CARGO_CRATE, _CARGO_GIT, _RUST_VENDOR):
        match = pattern.search(file)
        if match:
            return file[match.end():]
    match = _RUST_STD.search(file)
    if match:
        return file[match.start():].split("/", 3)[-1]
    if prefix and file.startswith(prefix):
        return file[len(prefix):]
    return file


def _program_prefix(files):
    """Common directory of the program's own files, so they print as project paths."""

    own = [file for file in files if origin(file)[0] == "program"]
    if not own:
        return ""
    prefix = posixpath.commonpath(own) if len(own) > 1 else posixpath.dirname(own[0])
    return prefix.rstrip("/") + "/" if prefix not in ("", "/") else ""


# -- views ------------------------------------------------------------------

def overview_lines(cmap, name, limit=40):
    """Files grouped by origin with their function counts."""

    located = cmap.located()
    prefix = _program_prefix(cmap.files)
    lines = [
        (f"Code map of {name}: {len(cmap.functions):,} functions, {len(located):,} located in "
        f"{len(cmap.files):,} source files (names and lines from {cmap.via})"),
    ]
    if not cmap.files:
        return lines + ["", ("No source locations: the binary has names but no line information "
                            "(no debug file for this build).")] + _namespace_lines(cmap, name, limit)

    groups = defaultdict(lambda: defaultdict(list))
    for file, functions in cmap.files.items():
        group, label = origin(file)
        groups[group][label].append((file, functions))

    def file_rows(entries, indent="  "):
        entries.sort(key=lambda item: (-len(item[1]), item[0]))
        rows = [f"{indent}{_short(file, prefix):<56} {len(functions):>5} function(s)" for file, functions in entries[:limit]]
        if len(entries) > limit:
            rows.append(f"{indent}... and {len(entries) - limit} more file(s)")
        return rows

    program = groups.get("program", {}).get(None, [])
    if program:
        count = sum(len(functions) for _, functions in program)
        lines += ["", f"Program: {len(program)} file(s), {count:,} function(s)" + (f"  ({prefix})" if prefix else "")]
        lines += file_rows(program)
    dependencies = groups.get("dependency", {})
    if dependencies:
        lines += ["", f"Dependencies: {len(dependencies)} crate(s) or package(s)"]
        ranked = sorted(dependencies.items(), key=lambda item: -sum(len(f) for _, f in item[1]))
        for label, entries in ranked[:limit]:
            lines.append(f"  {label:<40} {len(entries):>4} file(s) {sum(len(f) for _, f in entries):>6} function(s)")
        if len(ranked) > limit:
            lines.append(f"  ... and {len(ranked) - limit} more")
    for group in ("standard library", "system headers"):
        for label, entries in sorted(groups.get(group, {}).items()):
            lines.append("")
            lines.append(f"{label}: {len(entries)} file(s), {sum(len(f) for _, f in entries):,} function(s)")
    example_file = _short(max(program, key=lambda item: len(item[1]))[0], prefix) if program else None
    example_function = next((f.name for f in located if origin(f.file)[0] == "program" and "main" in f.name),
                            located[0].name if located else None)
    lines += ["", "Next"]
    if example_file:
        lines.append(f"  xray {name} --code {example_file}      a file, with the functions it defines")
    if example_function:
        lines.append(f"  xray {name} --code '{example_function}'      one function's code")
    lines.append(f"  xray {name} --callgraph               which function calls which, with files and lines")
    return lines


_LIBRARY_NAMESPACES = {"std", "__gnu_cxx", "__cxxabiv1", "__gnu_debug", "fmt", "boost", "core", "alloc"}


def _namespace_lines(cmap, name, limit):
    """Function names grouped by top-level namespace, the program's own first."""

    groups = defaultdict(list)
    for function in cmap.functions:
        base = re.sub(r"^(?:non-)?virtual thunk to |^covariant return thunk to ", "", _base(function.name))
        top = base.split("::", 1)[0] if "::" in base else "(global)"
        groups[top].append(function)
    own = sorted((k for k in groups if k not in _LIBRARY_NAMESPACES and not k.startswith("_")),
                 key=lambda k: (-len(groups[k]), k))
    other = sorted((k for k in groups if k not in own), key=lambda k: (-len(groups[k]), k))
    lines = ["", "Namespaces (the program's own first):"]
    for key in (own + other)[:limit]:
        lines.append(f"  {key:<40} {len(groups[key]):>6} function(s)")
    if len(groups) > limit:
        lines.append(f"  ... and {len(groups) - limit} more")
    sample = [f for key in own for f in groups[key]][:limit]
    if sample:
        lines += ["", "Some of the program's functions:"] + [f"  {f.name}" for f in sample]
    lines += ["", f"Machine code of one: xray {name} --disasm-function NAME (needs rizin)  ·  calls: xray {name} --disasm"]
    return lines


def find_file(cmap, wanted):
    """Files in the map whose path ends with wanted (path suffix or bare name)."""

    wanted = posixpath.normpath(wanted.lstrip("./")) if wanted not in (".", "") else wanted
    exact = [file for file in cmap.files if file == wanted]
    if exact:
        return exact
    return sorted(file for file in cmap.files if file.endswith("/" + wanted))


def _strip_generics(text):
    out, depth = [], 0
    for char in text:
        if char == "<":
            depth += 1
        elif char == ">" and depth:
            depth -= 1
        elif not depth:
            out.append(char)
    return "".join(out)


def _base(name):
    """Name as a reader would search for it, without generic arguments.

    a::b<T>::c::<U> -> a::b::c;  <a::B<T> as c::Trait>::m -> a::B::m;  <a::B<T>>::m -> a::B::m
    """

    name = name.split("(", 1)[0].strip()
    if name.startswith("<"):
        depth = 0
        for index, char in enumerate(name):
            depth += char == "<"
            depth -= char == ">"
            if depth == 0:
                inner, rest = name[1:index], name[index + 1:]
                inner = _strip_generics(inner).split(" as ", 1)[0].strip()
                name = inner + rest
                break
    base = _strip_generics(name)
    while "::::" in base:
        base = base.replace("::::", "::")
    base = base.strip(":").strip()
    if " " in base and not base.startswith(("virtual thunk", "non-virtual thunk", "covariant return")):
        base = base.rsplit(" ", 1)[-1]  # C++ template functions carry their return type: "void ns::f"
    return base


def find_functions(cmap, wanted):
    """Located functions matching wanted: exact name or symbol, then without generics, then a ::suffix."""

    located = cmap.located()
    for test in (
        lambda f: wanted in (f.name, f.symbol),
        lambda f: _base(f.name) == wanted,
        lambda f: _base(f.name).endswith("::" + wanted) or _base(f.name).endswith("." + wanted),
    ):
        found = [f for f in located if test(f)]
        if found:
            return found
    return []


_CRATES_URL = "https://static.crates.io/crates/{crate}/{crate}-{version}.crate"
_MAX_CRATE_BYTES = 64 * 1024 * 1024


_RUST_SRC_URL = "https://static.rust-lang.org/dist/rust-src-{version}.tar.xz"
_RUST_STD_VERSIONED = re.compile(r"/rustc-(?P<version>\d+\.\d+\.\d+)-src/library/(?P<inner>.+)$")


def _local_rust_library(version):
    """A local rust-src library/ tree for exactly this rustc version, or None."""

    candidates = sorted(Path.home().glob(f".rustup/toolchains/{version}-*/lib/rustlib/src/rust/library"))
    system = Path("/usr/lib/rustlib/src/rust/library")
    if system.is_dir() and shutil.which("rustc"):
        try:
            said = subprocess.run(["rustc", "-V"], capture_output=True, text=True, check=False, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            said = ""
        if said.split()[1:2] == [version]:
            candidates.append(system)
    return candidates[0] if candidates else None


def rust_std_source(file, fetch=None):
    """A Rust standard library file for the exact rustc version in the path, or None.

    A local rust-src of the same version is used when present; otherwise that
    version's rust-src archive (~6 MB) is downloaded once into the XRAY cache.
    """

    match = _RUST_STD_VERSIONED.search(file)
    if not match:
        return None
    version, inner = match["version"], match["inner"]
    if ".." in inner.split("/"):
        return None
    local = _local_rust_library(version)
    if local is not None and (local / inner).is_file():
        return local / inner
    from xray.evidencestore import cache_dir

    target = cache_dir() / "rust-src" / version / "library" / inner
    if target.is_file():
        return target
    archive_path = cache_dir() / "rust-src" / f"rust-src-{version}.tar.xz"
    if not archive_path.is_file():
        if fetch is None:
            fetch = _download
        try:
            data = fetch(_RUST_SRC_URL.format(version=version))
        except OSError:
            return None
        if not data or len(data) > _MAX_CRATE_BYTES:
            return None
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(data)
    import tarfile

    member_name = f"rust-src-{version}/rust-src/lib/rustlib/src/rust/library/{inner}"
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            member = archive.getmember(member_name)
            handle = archive.extractfile(member) if member.isfile() else None
            content = handle.read() if handle else None
    except (KeyError, OSError, tarfile.TarError):
        return None
    if content is None:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def _download(url):
    import urllib.request

    from xray import __version__

    request = urllib.request.Request(url, headers={"User-Agent": f"xray-trust/{__version__} (source viewer)"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(_MAX_CRATE_BYTES + 1)


def crate_source(file, fetch=None):
    """A Rust dependency's source file from its published crates.io archive, cached; or None.

    The DWARF path names the crate and exact version (.cargo/registry/src/<index>/<crate>-<version>/<path>).
    Only that one member is extracted, by exact name, into the XRAY cache.
    """

    match = _CARGO_CRATE.search(file) or _RUST_VENDOR.search(file)
    if not match:
        return None
    crate, version, inner = match["crate"], match["version"], file[match.end():]
    if not inner or ".." in inner.split("/"):
        return None
    from xray.evidencestore import cache_dir

    target = cache_dir() / "crates" / f"{crate}-{version}" / inner
    if target.is_file():
        return target
    if fetch is None:
        fetch = _download
    try:
        data = fetch(_CRATES_URL.format(crate=crate, version=version))
    except OSError:
        return None
    if not data or len(data) > _MAX_CRATE_BYTES:
        return None
    import io
    import tarfile

    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(f"{crate}-{version}/{inner}")
            if not member.isfile():
                return None
            handle = archive.extractfile(member)
            content = handle.read() if handle else None
    except (KeyError, OSError, tarfile.TarError):
        return None
    if content is None:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target


def fetch_source(cmap, file):
    """Local path of a source file: on this machine, from debuginfod, or (Rust crates) from crates.io."""

    if Path(file).is_file():
        return Path(file)
    if _CARGO_CRATE.search(file) or _RUST_VENDOR.search(file):
        return crate_source(file)
    if _RUST_STD_VERSIONED.search(file):
        found = rust_std_source(file)
        if found is not None:
            return found
    if cmap.build_id is None:
        from xray import debuginfod

        cmap.build_id = debuginfod.build_id(cmap.binary)
    if cmap.build_id is None:
        return None
    from xray import debuginfod

    return debuginfod.source_file(cmap.build_id, file)


def _language(file):
    suffix = Path(file).suffix.lower()
    if suffix == ".rs":
        return "rust"
    if suffix == ".go":
        return "go"
    return "c"


_RUST_CHAR = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'")
_RUST_RAW = re.compile(r'(?:b|c)?r(#*)"')


def body_end(lines, start, language="c", max_lines=2000):
    """1-based line closing the brace body that opens at or after start, or None.

    Strings, character literals and comments are skipped. Rust lifetimes ('a)
    are not character literals; Rust raw strings (r#"..."#) and Go raw strings
    (`...`) are skipped whole.
    """

    depth, opened, in_block, raw_end = 0, False, False, None
    for number in range(start, min(len(lines), start + max_lines) + 1):
        text, i = lines[number - 1], 0
        while i < len(text):
            if raw_end is not None:
                end = text.find(raw_end, i)
                if end < 0:
                    break
                i, raw_end = end + len(raw_end), None
                continue
            if in_block:
                end = text.find("*/", i)
                if end < 0:
                    break
                i, in_block = end + 2, False
                continue
            char = text[i]
            if text.startswith("//", i):
                break
            if text.startswith("/*", i):
                in_block, i = True, i + 2
                continue
            if language == "rust":
                raw = _RUST_RAW.match(text, i)
                if raw and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                    raw_end, i = '"' + raw.group(1), raw.end()
                    continue
            if language == "go" and char == "`":
                raw_end, i = "`", i + 1
                continue
            if char == '"':
                i += 1
                while i < len(text) and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
                i += 1
                continue
            if char == "'":
                if language == "rust":
                    match = _RUST_CHAR.match(text, i)
                    i = match.end() if match else i + 1  # otherwise a lifetime or label
                    continue
                i += 1
                while i < len(text) and text[i] != "'":
                    i += 2 if text[i] == "\\" else 1
                i += 1
                continue
            if char == "{":
                depth, opened = depth + 1, True
            elif char == "}":
                depth -= 1
                if opened and depth == 0:
                    return number
            i += 1
        if not opened and number >= start + 20:
            return None
    return None


def _definition_start(lines, hint, short):
    """The signature line near DWARF's line for a function (DWARF may point at the body)."""

    if not short:
        return hint
    word = re.compile(rf"\b{re.escape(short)}\b\s*[<(]")
    for number in range(min(hint, len(lines)), max(0, hint - 12), -1):
        if word.search(lines[number - 1]):
            start = number
            while start > 1 and lines[start - 2].strip().startswith(("#[", "pub", "///", "template", "static", "inline")) \
                    and not lines[start - 2].strip().endswith((";", "}")):
                start -= 1
            return start
    return hint


def function_code(cmap, function, max_lines=400):
    """(header, numbered lines) for one function's source, or None when the file can't be read."""

    local = fetch_source(cmap, function.file)
    if local is None:
        return None
    try:
        lines = local.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not function.line or function.line > len(lines):
        return None
    short = re.split(r"::|\.", _base(function.name))[-1]
    start = _definition_start(lines, function.line, short)
    end = body_end(lines, start, _language(function.file)) or min(len(lines), start + 40)
    shown = lines[start - 1:end]
    numbered = [f"{n:5d}  {text}" for n, text in enumerate(shown[:max_lines], start)]
    if len(shown) > max_lines:
        numbered.append(f"... and {len(shown) - max_lines} more lines")
    return f"{function.file}:{start} (source from {_where(function.file)})", numbered


def _where(file):
    if Path(file).is_file():
        return "this machine"
    if _CARGO_CRATE.search(file) or _RUST_VENDOR.search(file):
        return "crates.io"
    if _RUST_STD_VERSIONED.search(file):
        return "rust-src"
    return "debuginfod"


def function_view(cmap, wanted, name):
    """Lines for --code FUNCTION, or None when nothing in the map matches."""

    found = find_functions(cmap, wanted)
    if not found:
        return None
    # Compiler-split cold paths (".cold") point into inlined code; prefer the function itself.
    warm = [f for f in found if not re.search(r"\.cold\b", f.name + " " + f.symbol)]
    found = warm or found
    places = {}
    for function in found:
        places.setdefault((function.file, function.line), function)
    if len(places) > 1:
        lines = [f"{len(places)} functions match {wanted!r}; name one exactly:"]
        for (file, line), function in sorted(places.items(), key=lambda item: (item[0][0], item[0][1]))[:30]:
            lines.append(f"  {function.name}    {file}:{line}")
        if len(places) > 30:
            lines.append(f"  ... and {len(places) - 30} more")
        return lines
    function = next(iter(places.values()))
    shown = function_code(cmap, function)
    if shown is None:
        return [(f"{function.name} is defined at {function.file}:{function.line}, "
                "but that file is not on this machine and could not be fetched")]
    header, numbered = shown
    copies = len(found)
    lines = [function.name, header]
    if copies > 1:
        lines.append(f"({copies} compiled copies share this source, e.g. one per generic type)")
    return lines + [""] + numbered


def file_view(cmap, wanted, name, max_lines=2000):
    """Lines for --code FILE: the functions it defines, then its text. None when no file matches."""

    files = find_file(cmap, wanted)
    if not files:
        return None
    if len(files) > 1:
        return [f"{len(files)} files match {wanted!r}; give more of the path:"] + [f"  {file}" for file in files[:30]]
    file = files[0]
    functions = cmap.files[file]
    lines = [file, f"{len(functions)} function(s) compiled from this file:"]
    seen = set()
    for function in functions:
        key = (_base(function.name), function.line)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"  {function.line:>6}  {function.name}")
    local = fetch_source(cmap, file)
    if local is None:
        return lines + ["", "The file itself is not on this machine and could not be fetched."]
    text = local.read_text(encoding="utf-8", errors="replace").splitlines()
    where = _where(file)
    numbered = [f"{n:5d}  {line}" for n, line in enumerate(text[:max_lines], 1)]
    if len(text) > max_lines:
        numbered.append(f"... and {len(text) - max_lines} more lines")
    return lines + ["", f"Source ({len(text)} lines, from {where}):"] + numbered


# -- call graph ---------------------------------------------------------------

_GROUP_ORDER = {"program": 0, "dependency": 1, "standard library": 2, "system headers": 3, "import": 4, "?": 5}


def _entry(function, prefix):
    """(group, short readable name, place) for a function."""

    if function is None:
        return "?", "?", ""
    short = _base(function.name) or function.name
    if not function.file:
        return "program", short, ""
    return origin(function.file)[0], short, f"{_short(function.file, prefix)}:{function.line}"


def _is_cold(function):
    return bool(re.search(r"\.cold\b", function.name + " " + function.symbol))


def callgraph_lines(cmap, calls, name, focus=None, indirect=0, limit=60, per_function=12):
    """Which function calls which, with files and lines.

    calls maps a caller's symbol to the symbols (or name@plt imports) it calls
    directly, from disassembly; indirect calls (function pointers, vtables,
    trait objects) cannot be followed and are counted instead. Generic copies
    of one function are merged under its readable name.
    """

    by_symbol = {function.symbol: function for function in cmap.functions}
    prefix = _program_prefix(cmap.files)

    def entry(symbol):
        if symbol.endswith("@plt"):
            return "import", _base(_demangle([symbol[:-4]])[0]) or symbol[:-4], "shared library"
        return _entry(by_symbol.get(symbol), prefix)

    def rows(symbols, arrow):
        merged = {}
        for symbol in symbols:
            group, short, place = entry(symbol)
            key = (group, short)
            if key in merged:
                merged[key][2] += 1
            else:
                merged[key] = [place, group, 1]
        ordered = sorted(merged.items(), key=lambda item: (_GROUP_ORDER.get(item[0][0], 9), item[0][1]))
        out = []
        for (group, short), (place, _, copies) in ordered[:per_function]:
            note = f" ×{copies}" if copies > 1 else ""
            out.append(f"    {arrow} {short}{note}  ({place})" if place else f"    {arrow} {short}{note}")
        if len(ordered) > per_function:
            out.append(f"    ... and {len(ordered) - per_function} more")
        return out, len(ordered)

    callers_of = defaultdict(set)
    for caller, callees in calls.items():
        for callee in callees:
            callers_of[callee].add(caller)

    if focus is not None:
        found = find_functions(cmap, focus) or [f for f in cmap.functions if focus in (f.name, f.symbol, _base(f.name))]
        found = [f for f in found if not _is_cold(f)] or found
        if not found:
            return [f"No function named {focus!r} (see xray {name} --code for the map)"]
        groups = defaultdict(list)
        for function in found:
            groups[(_base(function.name), function.file, function.line)].append(function)
        lines = []
        for (short, file, line), copies in list(groups.items())[:5]:
            out = set().union(*(calls.get(f.symbol, ()) for f in copies))
            into = set().union(*(callers_of.get(f.symbol, set()) for f in copies))
            where = f"  ({_short(file, prefix)}:{line})" if file else ""
            out_rows, out_count = rows(out, "→")
            in_rows, in_count = rows(into, "←")
            lines += ["", f"{short}{where}" + (f"  [{len(copies)} compiled copies]" if len(copies) > 1 else ""),
                      f"  calls ({out_count}):"]
            lines += out_rows or ["    nothing directly"]
            lines.append(f"  called by ({in_count}):")
            lines += in_rows or ["    nothing directly (an entry point, or reached through a pointer)"]
        if len(groups) > 5:
            lines.append(f"... and {len(groups) - 5} more functions match {focus!r}")
        lines += ["", f"Indirect calls not followed: {indirect:,} (function pointers, vtables, trait objects)",
                  f"Read one: xray {name} --code NAME"]
        return lines[1:]

    own = [f for f in cmap.functions
           if f.symbol in calls and not _is_cold(f) and (f.file is None or origin(f.file)[0] == "program")]
    own.sort(key=lambda f: (f.file or "~", f.line or 0, f.name))
    total = sum(len(callees) for callees in calls.values())
    lines = [(f"{len(calls):,} functions make {total:,} direct calls; the program's own functions "
             f"({len(own):,}) file by file. Indirect calls not followed: {indirect:,}.")]
    current, shown = object(), set()
    count = 0
    for function in own:
        key = (_base(function.name), function.file, function.line)
        if key in shown:
            continue
        shown.add(key)
        if count >= limit:
            break
        count += 1
        if function.file != current:
            current = function.file
            lines += ["", _short(current, prefix) if current else "(no source location)"]
        out_rows, _ = rows(calls[function.symbol], "→")
        lines.append(f"  {key[0]}  (line {function.line})" if function.line else f"  {key[0]}")
        lines += out_rows
    if len(own) > count:
        lines.append(f"\n... more functions not shown (limit {limit}); pick one with --callgraph FUNCTION")
    lines += ["", f"One function, both directions: xray {name} --callgraph FUNCTION"]
    return lines


def elf_callgraph(path, focus=None):
    """--callgraph for a compiled program, or None when it has no function names."""

    from xray.disasm import disasm_result

    cmap = code_map(path)
    if cmap is None:
        return None
    found = disasm_result(path, timeout=120)
    if found is None:
        return ["objdump could not read this binary"]
    return callgraph_lines(cmap, found.calls, Path(path).name, focus, found.indirect)
