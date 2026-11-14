"""Haskell programs built by GHC: modules and functions from symbols, source from Hackage.

GHC names every top-level binding in the object code as

    <unit>_<Module>_<name>_<kind>        kind: info, closure, bytes, con_info, ...

with each part Z-encoded (``zi`` = ``.``, ``zm`` = ``-``, ``zu`` = ``_``,
``zd`` = ``$``, ``ZC`` = ``:``, ...), so names never contain a bare ``_``
and decode exactly. Distributions that link Haskell programs dynamically
(Arch) ship each package as ``libHS<package>-<version>-<hash>-ghc<v>.so``,
whose dynamic symbol table keeps these names even when the program is
stripped: ShellCheck's library names 2,000+ functions in 40 modules.

Names GHC makes itself (workers ``$w``, specialisations ``$s``, instance
methods ``$c``, floated bindings ``name12``, ``name_x3``, ``name_str4``)
are folded into the binding they come from; constructors are listed apart.

The package's source comes from its Hackage release (the version is in
the library name), downloaded once into the XRAY cache. A module's file
is found by its module path (``ShellCheck/Analytics.hs``), and a
function's definition by its top-level equations and type signature.
Calls between functions are found by name in the source, with comments
and strings blanked, and labelled so.
"""

import re
import subprocess
import tarfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_HACKAGE = "https://hackage.haskell.org/package/{package}-{version}/{package}-{version}.tar.gz"
_MAX_TARBALL = 64 * 1024 * 1024
_LIBRARY = re.compile(r"^libHS(?P<unit>.+?)-ghc(?P<ghc>[\d.]+)\.so$")
_UNIT = re.compile(r"^(?P<package>[A-Za-z][\w-]*?)-(?P<version>\d+(?:\.\d+)*)(?:-(?P<hash>[A-Za-z0-9]+))?$")
_KINDS = ("con_info", "con_entry", "static_info", "info", "closure", "bytes", "entry", "srt")
_LOWER = {"a": "&", "b": "|", "c": "^", "d": "$", "e": "=", "g": ">", "h": "#", "i": ".", "l": "<", "m": "-",
          "n": "!", "p": "+", "q": "'", "r": "\\", "s": "/", "t": "*", "u": "_", "v": "%", "z": "z"}
_UPPER = {"L": "(", "R": ")", "M": "[", "N": "]", "C": ":", "Z": "Z"}
_GENERATED = re.compile(r"^\$(?:w|s|c|f|tc|tr|m|b|d|W|p|l|x|j|t|krep|i|e|n)")
_FLOATED = re.compile(r"^(?P<base>.+?)(?:\d+|_x\d+|_str\d+|_s\d+|_go\d*|_\$\w*\d*)$")
BOOT = {"rts", "ghc-prim", "ghc-bignum", "base", "integer-gmp"}


_ZCODE = re.compile(r"[zZ](\d[0-9a-f]*)U|Z(\d+)([TH])|z[a-z]|Z[A-Z]")


def _zone(match):
    text = match.group()
    if match.group(1) is not None:
        return chr(int(match.group(1), 16))
    if match.group(2) is not None:
        commas = "," * (int(match.group(2)) - 1)
        return f"({commas})" if match.group(3) == "T" else f"(#{commas}#)"
    table = _LOWER if text[0] == "z" else _UPPER
    return table.get(text[1], text)


@lru_cache(maxsize=65536)
def zdecode(text):
    """GHC Z-decoding: "ShellCheckziAnalytics" -> "ShellCheck.Analytics"."""

    if "z" not in text and "Z" not in text:
        return text
    return _ZCODE.sub(_zone, text)


_SYMBOL = re.compile(r"^([^_]+)_([^_]+)_([^_]+)_(con_info|con_entry|static_info|info|closure|bytes|entry|srt)$")


def split_symbol(symbol):
    """(unit, module, name, kind) of a GHC symbol, or None."""

    match = _SYMBOL.match(symbol)
    if match is None:
        return None
    module = zdecode(match.group(2))
    if not module[:1].isupper():
        return None
    return zdecode(match.group(1)), module, zdecode(match.group(3)), match.group(4)


def unit_package(unit):
    """("ShellCheck", "0.11.0") from a unit id "ShellCheck-0.11.0-39iAT3…", or (unit, None)."""

    match = _UNIT.match(unit)
    return (match["package"], match["version"]) if match else (unit, None)


def binding_of(name, names):
    """The source binding a symbol name belongs to: generated names fold into their origin."""

    original = name
    for _ in range(4):
        generated = _GENERATED.match(name)
        if generated:
            name = name[generated.end():]
            continue
        floated = _FLOATED.match(name)
        if floated and floated["base"] in names and floated["base"] != name:
            name = floated["base"]
            continue
        break
    return name if name else original


@dataclass
class Package:
    name: str
    version: str | None
    library: Path
    modules: dict = field(default_factory=dict)        # module -> {binding: kind}
    constructors: dict = field(default_factory=dict)   # module -> set of constructors
    generated: int = 0

    @property
    def functions(self):
        return sum(len(bindings) for bindings in self.modules.values())


def _dynamic_symbols(path):
    try:
        result = subprocess.run(["nm", "-D", "--defined-only", "--format=just-symbols", str(path)],
                                capture_output=True, text=True, check=False, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return []
    return result.stdout.split()


@lru_cache(maxsize=32)
def _read_package(path, _size, _mtime):
    match = _LIBRARY.match(Path(path).name)
    unit = match["unit"] if match else Path(path).stem
    name, version = unit_package(unit)
    package = Package(name, version, Path(path))
    raw = {}
    for symbol in _dynamic_symbols(path):
        parts = split_symbol(symbol)
        if parts is None:
            continue
        _, module, binding, kind = parts
        raw.setdefault(module, {})[binding] = kind if kind not in ("closure", "bytes") or binding not in raw.get(
            module, {}) else raw[module][binding]
    for module, bindings in raw.items():
        names = {name for name in bindings if not _GENERATED.match(name)}
        kept = {}
        for binding, kind in bindings.items():
            if kind in ("con_info", "con_entry", "static_info") and binding[:1].isupper():
                package.constructors.setdefault(module, set()).add(binding)
                continue
            if binding[:1].isupper() or binding.startswith("$"):
                origin = binding_of(binding, names)
                if origin.startswith("$") or origin[:1].isupper():
                    package.generated += 1
                    continue
                binding = origin
            origin = binding_of(binding, names)
            if origin != binding:
                package.generated += 1
            if origin.startswith("'"):
                package.generated += 1  # a promoted constructor (DataKinds), not a function
                continue
            kept.setdefault(origin, kind)
        for binding in list(kept):
            floated = _FLOATED.match(binding)
            if floated and floated["base"] in kept and floated["base"] != binding:
                del kept[binding]
                package.generated += 1
        if kept:
            package.modules[module] = kept
    return package


def read_package(path):
    info = Path(path).stat()
    return _read_package(str(Path(path).resolve()), info.st_size, info.st_mtime_ns)


def _needed(path):
    from .elfscan import scan_elf

    try:
        return list(scan_elf(path).needed)
    except (OSError, ValueError):
        return []


def _find(soname, cache):
    from .libresolve import find_library

    found = find_library(soname, cache)
    return Path(found) if found else None


@dataclass
class Program:
    path: Path
    ghc: str
    own: list            # Package: the program's own code (same distribution package)
    dependencies: list   # Package: Hackage libraries it links
    boot: list           # sonames of GHC's runtime and boot libraries


def program(path):
    """The Haskell program at `path` (an ELF linking libHSrts, or a libHS library), or None."""

    path = Path(path)
    libraries = []
    if _LIBRARY.match(path.name):
        libraries = [path.name]
        own_names = {path.name}
    else:
        needed = _needed(path)
        if not any(soname.startswith("libHSrts") for soname in needed):
            return None
        libraries = [soname for soname in needed if _LIBRARY.match(soname)]
        own_names = set()
    ghc = next((m["ghc"] for m in map(_LIBRARY.match, libraries) if m), "")
    wanted = {path.name.lower()}
    if not own_names:
        from .provenance import package_of

        owner = package_of(path)
        if owner:
            wanted.add(str(owner).split()[0].lower().removeprefix("haskell-"))
    from .libresolve import ldconfig_cache

    cache = ldconfig_cache()
    own, dependencies, boot = [], [], []
    located = {}
    for soname in libraries:
        unit = _LIBRARY.match(soname)["unit"]
        if unit_package(unit)[0] in BOOT or unit.startswith("rts"):
            boot.append(soname)
            continue
        found = path if soname in own_names else _find(soname, cache)
        if found is not None:
            located[soname] = found
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=8) as pool:
        packages = dict(zip(located, pool.map(read_package, located.values())))
    for soname, package in packages.items():
        name = package.name
        mine = soname in own_names or name.lower() in wanted
        (own if mine else dependencies).append(package)
    return Program(path, ghc, own, dependencies, boot)


# -- source from Hackage --------------------------------------------------------


def _download(url):
    from .codemap import _download as download

    return download(url)


def tarball(package, fetch=None):
    """Path of the package's Hackage source archive in the cache (downloaded once), or None."""

    if package.version is None or not re.fullmatch(r"[\w-]+", package.name):
        return None
    from .evidencestore import cache_dir

    target = cache_dir() / "hackage" / f"{package.name}-{package.version}.tar.gz"
    if target.is_file():
        return target
    try:
        data = (fetch or _download)(_HACKAGE.format(package=package.name, version=package.version))
    except OSError:
        return None
    if not data or len(data) > _MAX_TARBALL:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


@lru_cache(maxsize=16)
def _members(archive):
    try:
        with tarfile.open(archive, mode="r:gz") as handle:
            return {member.name: member for member in handle.getmembers() if member.isfile()}
    except (OSError, tarfile.TarError):
        return {}


def module_file(archive, module):
    """The member name of `module`'s source in the archive (shortest path ending in Module/Path.hs)."""

    tail = module.replace(".", "/")
    found = [name for name in _members(str(archive))
             if re.search(rf"(^|/){re.escape(tail)}\.(hs|lhs|hsc|hs-boot)$", name) and ".." not in name.split("/")]
    found.sort(key=lambda name: (name.endswith(".hs-boot"), len(name)))
    return found[0] if found else None


def read_member(archive, name):
    member = _members(str(archive)).get(name)
    if member is None:
        return None
    with tarfile.open(archive, mode="r:gz") as handle:
        stream = handle.extractfile(member)
        data = stream.read() if stream else b""
    return data.decode("utf-8", errors="replace")


def blank(lines):
    """Lines with Haskell comments and string/char literals replaced by spaces (same columns)."""

    out = []
    depth = 0
    for line in lines:
        chars = list(line)
        index = 0
        in_string = False
        while index < len(chars):
            pair = line[index:index + 2]
            if depth:
                if pair == "{-":
                    depth += 1
                    chars[index] = chars[index + 1] = " "
                    index += 2
                    continue
                if pair == "-}":
                    depth -= 1
                    chars[index] = chars[index + 1] = " "
                    index += 2
                    continue
                chars[index] = " "
                index += 1
                continue
            if in_string:
                if line[index] == "\\":
                    chars[index] = " "
                    if index + 1 < len(chars):
                        chars[index + 1] = " "
                    index += 2
                    continue
                if line[index] == '"':
                    in_string = False
                chars[index] = " " if line[index] != '"' else '"'
                index += 1
                continue
            if pair == "{-":
                depth += 1
                chars[index] = chars[index + 1] = " "
                index += 2
                continue
            if pair == "--" and not re.match(r"--+[!#$%&*+./<=>?@\\^|~:]", line[index:]):
                for rest in range(index, len(chars)):
                    chars[rest] = " "
                break
            if line[index] == '"':
                in_string = True
            elif re.match(r"'(?:[^'\\]|\\[^']+)'", line[index:]) and (index == 0 or not line[index - 1].isalnum()):
                end = index + re.match(r"'(?:[^'\\]|\\[^']+)'", line[index:]).end()
                for rest in range(index + 1, end - 1):
                    chars[rest] = " "
                index = end
                continue
            index += 1
        out.append("".join(chars))
    return out


_DEFINES = re.compile(r"^(?P<name>[a-z_][\w']*|\([^)\s]+\))(?=[\s=|:]|$)")
_BINDS = re.compile(r"(?<![=<>/!:])=(?![=>])|::|^\s*\S+[^|]*\|(?!\|)")
_KEYWORDS = {"import", "module", "data", "type", "newtype", "class", "instance", "deriving", "infixl", "infixr",
             "infix", "where", "let", "in", "if", "then", "else", "case", "of", "do", "foreign", "default"}


def definitions(lines):
    """{name: (first line, last line)} of top-level bindings (signature and every equation)."""

    clean = blank(lines)
    starts = []
    for number, text in enumerate(clean, 1):
        if not text or text[0].isspace():
            continue
        match = _DEFINES.match(text)
        name = match["name"].strip("()") if match else None
        if name in _KEYWORDS or name is None:
            starts.append((number, None))
            continue
        starts.append((number, name))
    spans = {}
    for index, (number, name) in enumerate(starts):
        if name is None:
            continue
        end = (starts[index + 1][0] - 1) if index + 1 < len(starts) else len(lines)
        while end > number and not clean[end - 1].strip():
            end -= 1
        if not _BINDS.search(" ".join(clean[number - 1:end])):
            continue  # a top-level expression (a Template Haskell splice), not a definition
        first, last = spans.get(name, (number, end))
        spans[name] = (min(first, number), max(last, end))
    return spans


@dataclass
class Module:
    name: str
    package: Package
    member: str
    lines: list
    spans: dict
    clean: list = field(default_factory=list)


@lru_cache(maxsize=256)
def _load(package_name, version, library, module, archive):
    member = module_file(archive, module)
    if member is None:
        return None
    text = read_member(archive, member)
    if text is None:
        return None
    lines = text.splitlines()
    return member, lines, definitions(lines), blank(lines)


def load_module(package, module, fetch=None):
    archive = tarball(package, fetch)
    if archive is None:
        return None
    loaded = _load(package.name, package.version, str(package.library), module, str(archive))
    if loaded is None:
        return None
    member, lines, spans, clean = loaded
    return Module(module, package, member, lines, spans, clean)


def main_source(prog, fetch=None):
    """(package, member, lines) of the executable's Main module, from its package's .cabal file."""

    for package in prog.own:
        archive = tarball(package, fetch)
        if archive is None:
            continue
        cabal = next((name for name in _members(str(archive)) if name.count("/") == 1 and name.endswith(".cabal")),
                     None)
        text = read_member(archive, cabal) if cabal else None
        if not text:
            continue
        sections = re.split(r"(?im)^(?=executable\s)", text)
        for section in sections[1:]:
            header = section.split("\n", 1)[0].split()
            if len(header) < 2 or header[1].lower() != prog.path.name.lower():
                continue
            main = re.search(r"(?im)^\s+main-is:\s*(\S+)", section)
            dirs = re.search(r"(?im)^\s+hs-source-dirs:\s*(\S+)", section)
            if not main:
                continue
            root = cabal.split("/")[0]
            for candidate in ([f"{root}/{dirs.group(1).rstrip(',')}/{main.group(1)}"] if dirs else []) + \
                    [f"{root}/{main.group(1)}"]:
                content = read_member(archive, candidate)
                if content is not None:
                    return package, candidate, content.splitlines()
    return None


# -- views ----------------------------------------------------------------------


def _label(package):
    return f"{package.name} {package.version}" if package.version else package.name


def overview_lines(prog):
    lines = [f"Haskell (GHC {prog.ghc}) program" if prog.ghc else "Haskell program"]
    for package in prog.own:
        lines.append(f"- own code: {_label(package)}, {len(package.modules)} modules, {package.functions} functions "
                     f"(from {package.library.name})")
    if prog.dependencies:
        names = ", ".join(_label(p) for p in prog.dependencies[:12])
        lines.append(f"- {len(prog.dependencies)} Hackage libraries: {names}"
                     + (" …" if len(prog.dependencies) > 12 else ""))
    if prog.boot:
        lines.append(f"- GHC runtime and boot libraries: {len(prog.boot)}")
    lines.append(f"Read it: xray {prog.path} --code   (modules, then --code MODULE or --code FUNCTION)")
    return lines


def map_lines(prog, limit=60):
    lines = overview_lines(prog)[:-1]
    for heading, packages in (("Own code", prog.own), ("Libraries", prog.dependencies)):
        if not packages:
            continue
        lines += ["", f"{heading}:"]
        for package in packages:
            lines.append(f"  {_label(package)}  ({len(package.modules)} modules, {package.functions} functions; "
                         f"{package.library})")
            if heading == "Own code" or len(prog.own) == 0:
                for module in sorted(package.modules)[:limit]:
                    count = len(package.modules[module])
                    lines.append(f"    {module}  ({count} function{'s' if count != 1 else ''})")
                if len(package.modules) > limit:
                    lines.append(f"    ... and {len(package.modules) - limit} more modules")
    main = main_source(prog) if prog.own and not _LIBRARY.match(prog.path.name) else None
    if main is not None:
        lines += ["", (f"Main module (in the executable itself): {main[1]}, {len(main[2])} lines, from the "
                       f"package's .cabal file; xray {prog.path} --code Main")]
    lines += ["", "Names come from the libraries' symbol tables; source from Hackage (the exact version).",
              f"One module: xray {prog.path} --code MODULE      One function: xray {prog.path} --code FUNCTION",
              f"Calls: xray {prog.path} --callgraph FUNCTION"]
    return lines


def _packages(prog):
    return [*prog.own, *prog.dependencies]


def find_module(prog, wanted):
    for package in _packages(prog):
        if wanted in package.modules:
            return package
    return None


def find_function(prog, wanted):
    """[(package, module, name)] for 'name' or 'Module.name'."""

    module_part, _, name = wanted.rpartition(".") if "." in wanted and wanted[:1].isupper() else ("", "", wanted)
    found = []
    for package in _packages(prog):
        for module, bindings in package.modules.items():
            if module_part and module != module_part:
                continue
            if name in bindings:
                found.append((package, module, name))
    own = [entry for entry in found if entry[0] in prog.own]
    return own or found


def _numbered(lines, start=1, limit=400):
    shown = [f"{number:5d}  {line}" for number, line in enumerate(lines[:limit], start)]
    if len(lines) > limit:
        shown.append(f"... and {len(lines) - limit} more lines")
    return shown


def module_lines(prog, package, module, fetch=None):
    loaded = load_module(package, module, fetch)
    names = sorted(package.modules.get(module, {}))
    head = [f"{module} ({_label(package)})", f"{len(names)} functions in the symbol table: "
            + ", ".join(names[:40]) + (" …" if len(names) > 40 else "")]
    if loaded is None:
        return [*head, "", f"Source not available (Hackage {package.name}-{package.version} could not be read)"]
    return [*head, f"Source: Hackage {package.name}-{package.version}, {loaded.member}", "",
            *_numbered(loaded.lines, limit=600)]


def function_lines(prog, wanted, fetch=None):
    matches = find_function(prog, wanted)
    if not matches:
        return None
    out = []
    for package, module, name in matches[:3]:
        loaded = load_module(package, module, fetch)
        title = f"{module}.{name} ({_label(package)})"
        if loaded is None:
            out += [title, "  in the symbol table; source not available from Hackage", ""]
            continue
        span = loaded.spans.get(name)
        if span is None:
            out += [title, (f"  in the symbol table; no top-level definition in {loaded.member} "
                            "(defined in a where block, by Template Haskell or by deriving)"), ""]
            continue
        start, end = span
        out += [f"{title}: {loaded.member}, lines {start}–{end} (Hackage source of the exact version)", "",
                *_numbered(loaded.lines[start - 1:end], start), ""]
    if len(matches) > 3:
        out.append(f"... and {len(matches) - 3} more modules define {wanted}: "
                   + ", ".join(f"{m}.{n}" for _, m, n in matches[3:12]))
    return out


def code_lines(prog, name=None, fetch=None):
    if name is None:
        return map_lines(prog)
    if name == "Main":
        main = main_source(prog, fetch)
        if main is not None:
            package, member, lines = main
            return [f"Main ({_label(package)}): {member} (Hackage source of the exact version)", "",
                    *_numbered(lines, limit=600)]
    package = find_module(prog, name)
    if package is not None:
        return module_lines(prog, package, name, fetch)
    found = function_lines(prog, name, fetch)
    if found:
        return found
    return [f"No module or function named {name!r} in {prog.path.name}'s Haskell packages"]


def _words(names):
    alternatives = "|".join(sorted(map(re.escape, names), key=len, reverse=True))
    return re.compile(r"(?<![\w'.])(" + alternatives + r")(?![\w'])")


def _body_calls(loaded, caller, pattern):
    """{callee: [lines]} for names `pattern` matches in caller's definition (not at a line's start)."""

    clean = loaded.clean
    start, end = loaded.spans[caller]
    found = {}
    for number in range(start, end + 1):
        for match in pattern.finditer(clean[number - 1]):
            callee = match.group(1)
            if callee != caller and match.start() > 0:
                found.setdefault(callee, []).append(number)
    return found


_BINDER = re.compile(r"^\s+(?:let\s+|where\s+)?([a-z_][\w']*)\b[^=\n]*?(?<![=<>/!:])=(?![=>])")


def _local_binders(loaded, caller):
    """Names a definition binds for itself (where, let): calls to them are not calls out."""

    start, end = loaded.spans[caller]
    return {m.group(1) for line in loaded.clean[start:end] if (m := _BINDER.match(line))}


def _imports(loaded, module):
    return re.search(rf"^import\s+(?:qualified\s+)?{re.escape(module)}(?![\w.])", "\n".join(loaded.clean), re.MULTILINE)


def callgraph_lines(prog, focus=None, fetch=None, per_function=25):
    if focus is None:
        return [*map_lines(prog)[:6], "", (f"Give a function: xray {prog.path} --callgraph FUNCTION "
                                           "(calls inside its package, both directions)")]
    matches = find_function(prog, focus)
    if not matches:
        return [f"No function named {focus!r} in {prog.path.name}'s Haskell packages"]
    package, module, name = matches[0]
    loaded = load_module(package, module, fetch)
    if loaded is None or name not in loaded.spans:
        return [f"{module}.{name}: no source definition to read calls from"]
    modules = {module: loaded}
    for other in package.modules:
        if other != module:
            found = load_module(package, other, fetch)
            if found is not None:
                modules[other] = found
    homes = {}
    for other, found in modules.items():
        for defined in found.spans:
            homes.setdefault(defined, []).append(other)

    def home_of(name_, in_module):
        places = homes.get(name_, [])
        if in_module in places:
            return in_module
        imported = [m for m in places if _imports(modules[in_module], m)]
        return imported[0] if len(imported) == 1 else None

    names = [n for n in homes if len(n) > 1]
    start, end = loaded.spans[name]
    out = [(f"{module}.{name}  ({loaded.member}, lines {start}–{end}; {_label(package)}; "
            "calls found by name in the source)")]
    local = _local_binders(loaded, name)
    callees = {callee: lines for callee, lines in _body_calls(loaded, name, _words(names)).items()
               if callee not in local and home_of(callee, module)}

    def where(callee):
        home = home_of(callee, module)
        return (home != module, home, modules[home].spans[callee][0])

    for callee in sorted(callees, key=where)[:per_function]:
        home = home_of(callee, module)
        at = ", ".join(map(str, callees[callee][:6]))
        line = modules[home].spans[callee][0]
        place = f"line {line}" if home == module else f"{home}, line {line}"
        out.append(f"  → {callee}  ({place}; called at {at})")
    if len(callees) > per_function:
        out.append(f"  ... and {len(callees) - per_function} more")
    single = _words([name])
    callers = []
    for other, found in modules.items():
        if other != module and not _imports(found, module):
            continue
        if other != module and name in found.spans:
            continue  # that module has its own binding of this name
        for caller in found.spans:
            if caller == name and other == module:
                continue
            if name in _local_binders(found, caller):
                continue
            hits = _body_calls(found, caller, single).get(name)
            if hits:
                callers.append((other != module, other, found.spans[caller][0], caller, hits))
    out.append(f"  called by ({len(callers)}):")
    for _, other, _, caller, hits in sorted(callers)[:per_function]:
        place = "" if other == module else f"{other}, "
        out.append(f"    ← {caller}  ({place}line {', '.join(map(str, hits[:6]))})")
    if len(callers) > per_function:
        out.append(f"    ... and {len(callers) - per_function} more")
    if not callers:
        out.append(f"    nothing in {package.name} (exported for other packages, or used through a class)")
    return out
