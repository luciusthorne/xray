import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

from xray.analysis_cache import cache_home
from xray.entrypoints import command_kind
from xray.minidebug import read_function_table
from xray.provenance import package_of

# Folders holding a separate or non-installed implementation of the same
# names (gmp ships a simplified mini-gmp); never the code of the build.
SKIPPED_DIRS = {"mini-gmp"}

VARIANT = re.compile(r"(\.(isra|constprop|part|cold|lto_priv)(\.\d+)?)+$")
_CACHE_MUTEX = threading.RLock()
_CACHE_LOCK_STATE = threading.local()


def base_name(name):
    """Strip compiler suffixes such as .isra.0 or .cold: they are not in source."""

    return VARIANT.sub("", name)


def cache_root():
    return cache_home() / "src"


@contextmanager
def _cache_lock():
    """Serialize source-cache use and mutation across XRAY processes on Unix."""
    import fcntl

    with _CACHE_MUTEX:
        depth = getattr(_CACHE_LOCK_STATE, "depth", 0)
        if depth:
            _CACHE_LOCK_STATE.depth += 1
            try:
                yield
            finally:
                _CACHE_LOCK_STATE.depth -= 1
            return
        root = cache_root()
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink():
            raise ValueError("source cache root must not be a symlink")
        with (root / ".lock").open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            _CACHE_LOCK_STATE.depth = 1
            try:
                yield
            finally:
                _CACHE_LOCK_STATE.depth = 0
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def source_cache_entries():
    """Return completed cached source trees and their on-disk sizes."""
    root = cache_root()
    if not root.exists():
        return []
    with _cache_lock():
        entries = []
        for path in sorted(root.iterdir()):
            if path.is_dir() and not path.is_symlink() and (path / ".done").is_file():
                size = _tree_size(path)
                entries.append((path.name, size))
        return entries


def remove_source_cache(name=None):
    """Remove completed source trees; refuse unsafe names and symlinks."""
    root = cache_root()
    if not root.exists():
        return 0
    if root.is_symlink():
        raise ValueError("source cache root must not be a symlink")
    if name is not None and (name in {"", ".", ".."} or Path(name).name != name):
        raise ValueError("invalid source cache package name")
    with _cache_lock():
        targets = [root / name] if name is not None else list(root.iterdir())
        removed = 0
        for path in targets:
            if path.is_symlink():
                raise ValueError(f"refusing to remove symlink: {path.name}")
            if path.name == ".lock":
                continue
            if path.is_dir():
                shutil.rmtree(path)
                removed += 1
            elif path.exists():
                raise ValueError(f"refusing to remove non-directory cache entry: {path.name}")
        return removed


def _tree_size(root):
    """Count regular files without following symlinks out of the cache tree."""
    return sum(
        path.stat().st_size
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def _top_level_lines(lines):
    """Yield source lines with their brace depth before that line."""
    depth = 0
    for index, line in enumerate(lines):
        yield index, depth
        if not line.lstrip().startswith("#"):
            depth = max(0, depth + line.count("{") - line.count("}"))


_TEST_DIRS = {"test", "tests", "testsuite", "gnulib-tests", "examples", "demos", "doc"}


def binary_stems(path):
    """Source file stems that most likely hold a binary's own code."""
    stem = Path(path).name.split(".", 1)[0]
    stems = {stem}

    if stem.startswith("lib") and len(stem) > 3:
        stems.add(stem[3:])

    return stems


def _definition_rank(root, path, prefer):
    """Sort key: the binary's own file first, test and example code last."""
    parts = set(path.relative_to(root).parts[:-1])

    return (path.stem not in prefer, bool(parts & _TEST_DIRS))


def find_definition(root, name, max_lines=120, prefer=()):
    """Find a C function definition under root.

    Returns (file, first line number, lines, others) or None. Matches a
    function name in its declaration and requires a body brace before
    a terminating semicolon, so prototypes are skipped. The line above
    is included when it holds the return type. others counts further
    matches in other places. When several files define the name, a file
    whose stem is in prefer wins, and test or example folders lose.
    """

    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    found = []

    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)

        for filename in sorted(files):
            if not filename.endswith((".c", ".h")):
                continue

            path = Path(folder) / filename

            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for index, depth in _top_level_lines(lines):
                line = lines[index]
                if depth or not pattern.search(line):
                    continue

                end = _body_end(lines, index)

                if end is not None:
                    found.append((path, index, end, lines))

    if not found:
        return find_macro_definition(root, name, max_lines)

    found.sort(key=lambda item: _definition_rank(root, item[0], prefer))
    path, index, end, lines = found[0]
    start = index

    if index > 0:
        above = lines[index - 1].rstrip()

        if above and not above.startswith(("#", "}", "/")) and not above.endswith((";", "*/")):
            start = index - 1

    shown = lines[start : end + 1]

    if len(shown) > max_lines:
        shown = shown[:max_lines] + [f"... and {len(shown) - max_lines} more lines"]

    return path, start + 1, shown, len(found) - 1


def find_definition_file(path, name, max_lines=120):
    """Find one top-level C function in a specific source file."""
    path = Path(path)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    matches = []
    for index, depth in _top_level_lines(lines):
        if not depth and pattern.search(lines[index]):
            end = _body_end(lines, index)
            if end is not None:
                matches.append((index, end))
    if not matches:
        return None

    index, end = matches[0]
    start = index
    if index > 0:
        above = lines[index - 1].rstrip()
        if above and not above.startswith(("#", "}", "/")) and not above.endswith((";", "*/")):
            start = index - 1
    shown = lines[start : end + 1]
    if len(shown) > max_lines:
        shown = shown[:max_lines] + [f"... and {len(shown) - max_lines} more lines"]
    return path, start + 1, shown, len(matches) - 1


def find_macro_definition(root, name, max_lines=120):
    """Find a function body generated by a simple object-like C macro."""
    define = re.compile(
        rf"^\s*#\s*define\s+(\w+)\s+{re.escape(name)}\s*$"
    )
    found = []

    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)

        for filename in sorted(files):
            if not filename.endswith((".c", ".h")):
                continue

            path = Path(folder) / filename

            try:
                lines = path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                continue

            definitions = {
                match.group(1): index
                for index, line in enumerate(lines)
                if (match := define.match(line))
            }

            if not definitions:
                continue

            for index, line in enumerate(lines):
                match = re.match(r"^(\w+)\s*\(", line)

                if not match or match.group(1) not in definitions:
                    continue

                end = _body_end(lines, index)

                if end is not None:
                    define_index = definitions[match.group(1)]
                    context_start = define_index

                    while context_start > 0:
                        previous = lines[context_start - 1].strip()

                        if previous.startswith(("#ifdef ", "#if ")):
                            context_start -= 1
                            break

                        if previous and not previous.startswith("#"):
                            break

                        context_start -= 1

                    selected = lines[context_start:define_index + 1]
                    body = lines[index:end + 1]
                    shown = selected + ["/* shared macro-generated body */"] + body
                    found.append((path, context_start, end, lines, shown))
                    break

    if not found:
        return None

    path, index, end, lines, shown = found[0]

    if len(shown) > max_lines:
        shown = shown[:max_lines] + [
            f"... and {len(shown) - max_lines} more lines"
        ]

    return path, index + 1, shown, len(found) - 1

def _body_end(lines, index):
    depth = 0

    for j in range(index, min(index + 2000, len(lines))):
        line = lines[j]
        had_body = depth > 0
        depth += line.count("{") - line.count("}")
        if (had_body or "{" in line) and depth == 0:
            return j
        if depth > 0:
            continue
        if depth < 0:
            return None
        if line.rstrip().endswith(";"):
            return None

    return None


def _query(path):
    try:
        result = subprocess.run(
            ["rpm", "-qf", "--qf", r"%{NAME}-%{VERSION}-%{RELEASE}\n%{SOURCERPM}\n", str(path)],
            capture_output=True, text=True, errors="replace", check=False,
        )
    except OSError:
        return None

    parts = result.stdout.split()

    if result.returncode != 0 or len(parts) < 2 or parts[1] == "(none)":
        return None

    return parts[0], parts[1].removesuffix(".rpm")


SOURCE_DOWNLOAD_LIMIT = 10 * 1024 * 1024


def source_rpm_size(nvr):
    """Return the source RPM download size in bytes, or None if unknown."""

    try:
        result = subprocess.run(
            [
                "dnf", "repoquery", "--srpm",
                "--queryformat", "%{downloadsize}", nvr,
            ],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    value = result.stdout.strip()

    if result.returncode != 0 or not value.isdigit():
        return None

    return int(value)


def confirm_source_download(
    size, say, max_bytes=SOURCE_DOWNLOAD_LIMIT, input_fn=input
):
    """Confirm oversized downloads; warn and proceed if size is unknown."""

    if size is None:
        say("Source package size is unknown; proceeding without a size check.")
        return True

    if size <= max_bytes:
        return True

    mib = 1024 * 1024
    say(
        f"Source package is large: {size / mib:.1f} MiB "
        f"(limit {max_bytes / mib:.1f} MiB)."
    )

    try:
        answer = input_fn("Download and extract it anyway? [y/N] ")
    except (EOFError, OSError):
        answer = ""

    if answer.strip().lower() not in {"y", "yes"}:
        say("Source download cancelled.")
        return False

    return True


def ensure_source(nvr, stem, say):
    """Return the unpacked source folder for a package, downloading once."""

    with _cache_lock():
        target = _ensure_source_locked(nvr, stem, say)
        _prune_source_cache(target)
        return target


def _ensure_source_locked(nvr, stem, say):
    """Populate one cache entry while the caller holds the cache lock."""

    if stem in {"", ".", ".."} or Path(stem).name != stem:
        raise ValueError("invalid source package cache name")

    target = cache_root() / stem

    if (target / ".done").is_file():
        os.utime(target / ".done", None)
        return target

    size = source_rpm_size(nvr)

    if not confirm_source_download(size, say):
        raise FileNotFoundError("source download cancelled by user")

    say(f"Downloading source package for {nvr} (cached afterwards)")

    with tempfile.TemporaryDirectory() as work:
        subprocess.run(
            ["dnf", "download", "--source", nvr, "--destdir", work],
            capture_output=True, text=True, check=True, timeout=300,
        )
        srpms = list(Path(work).glob("*.src.rpm"))

        if not srpms:
            raise FileNotFoundError("no source package was downloaded")

        subprocess.run(
            f"rpm2cpio {shlex.quote(str(srpms[0]))} | cpio -idm",
            shell=True, cwd=work, capture_output=True, check=True, timeout=300,
        )
        tarballs = [
            p for p in Path(work).glob("*.tar.*")
            if not p.name.endswith((".sig", ".asc"))
        ]

        if not tarballs:
            raise FileNotFoundError("the source package holds no tarball")

        root = cache_root()
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=f".{stem}-", dir=root) as staging:
            staging = Path(staging)
            with tarfile.open(max(tarballs, key=lambda p: p.stat().st_size)) as archive:
                archive.extractall(staging, filter="data")
            (staging / ".done").write_text("ok\n", encoding="utf-8")
            if target.exists():
                shutil.rmtree(target)
            os.replace(staging, target)

    return target


def _prune_source_cache(preserve):
    """Enforce optional XRAY_SOURCE_CACHE_MAX_MIB using least-recently-used trees."""
    configured = os.environ.get("XRAY_SOURCE_CACHE_MAX_MIB")
    if configured is None:
        return
    try:
        limit = int(configured) * 1024 * 1024
    except ValueError as error:
        raise ValueError("XRAY_SOURCE_CACHE_MAX_MIB must be a non-negative integer") from error
    if limit < 0:
        raise ValueError("XRAY_SOURCE_CACHE_MAX_MIB must be a non-negative integer")
    root = cache_root()
    trees = [p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and (p / ".done").is_file()]
    sizes = {path: _tree_size(path) for path in trees}
    total = sum(sizes.values())
    for path in sorted(
        (p for p in trees if p != preserve),
        key=lambda p: (p / ".done").stat().st_mtime_ns,
    ):
        if total <= limit:
            break
        shutil.rmtree(path)
        total -= sizes[path]


def _may_be_exported(name, plain, known):
    """True if the name is exported, or might be a header alias of an export.

    A name inside an exported symbol (mpz_add in __gmpz_add) passes, so the
    source can be searched for the alias. Short names must match exactly.
    """

    if name in known or plain in {base_name(n) for n in known}:
        return True

    return len(plain) >= 4 and any(plain in n for n in known)


def _source_package_unavailable(path):
    package = package_of(path)

    if package is not None:
        return (
            f"Package {package} owns this file, but source package lookup "
            "currently supports RPM packages with source metadata only"
        )

    return "No installed package owns this file, so there is no source package"


def local_source_roots():
    """Return user-configured source trees from XRAY_SOURCE_PATH."""
    configured = os.environ.get("XRAY_SOURCE_PATH", "")
    roots = []
    for item in configured.split(os.pathsep):
        if not item.strip():
            continue
        root = Path(item).expanduser()
        if root.is_dir():
            roots.append(root.resolve())
    return roots


def source_lines(path, name, say=lambda text: None, max_lines=120):
    """Return the C source of a function of an installed binary.

    The package comes from rpm, its source package is downloaded once
    into the cache, and the definition is searched by name. The code
    is upstream code: Fedora patches may make it differ from what is
    installed.
    """

    with _cache_lock():
        return _source_lines_locked(path, name, say, max_lines)


def _source_lines_locked(path, name, say, max_lines):
    path = Path(path)

    if command_kind(path) != "elf":
        return ["Not an ELF binary: --source reads ELF only"]

    known = {entry[2] for entry in read_function_table(path)}
    plain = base_name(name)

    for root in local_source_roots():
        alias = elf_alias(root, plain, known) if known else None
        result = find_definition(root, plain, max_lines, binary_stems(path))
        if result is None and alias:
            result = find_definition(root, alias, max_lines, binary_stems(path))
        if result is not None:
            file, line, shown, others = result
            header = [f"{file.relative_to(root)}:{line}", "(local source tree)"]
            if plain != name:
                header.append(f"({name} is a compiler variant of {plain})")
            if alias:
                header.append(f"({plain} is exported as {alias})")
            if others:
                header.append(f"({others} more match(es) elsewhere; showing the most likely)")
            return header + shown

    try:
        from xray.debuginfod import configured, function_source

        if configured():
            say("Querying configured debuginfod servers for function source")
            remote = function_source(path, name)
            if remote is not None:
                source_name, cached_source, _line_hint = remote
                result = find_definition_file(cached_source, plain, max_lines)
                if result is not None:
                    _file, line, shown, others = result
                    header = [f"{source_name}:{line}", "(source from debuginfod)"]
                    if plain != name:
                        header.append(f"({name} is a compiler variant of {plain})")
                    if others:
                        header.append(f"({others} more match(es) in this file)")
                    return header + shown
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        pass

    if known and not _may_be_exported(name, plain, known):
        return [f"Unknown function: {name[:60]} (see --disasm for names)"]

    info = _query(path.resolve())

    if info is None:
        return [_source_package_unavailable(path.resolve())]

    nvr, stem = info

    try:
        root = ensure_source(nvr, stem, say)
    except FileNotFoundError as error:
        return [f"Source not available: {error}"]
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return [f"Could not fetch the source package: {error}"]

    alias = None

    if known and plain not in known:
        alias = elf_alias(root, plain, known)

    result = find_definition(root, plain, max_lines, binary_stems(path.resolve()))

    if result is None:
        message = f"No definition of {plain} found in the source of {nvr}"

        if alias:
            message += f" (it is exported as {alias})"

        return [message]

    file, line, shown, others = result
    header = [f"{file.relative_to(root)}:{line}"]

    if plain != name:
        header.append(f"({name} is a compiler variant of {plain})")

    if alias:
        header.append(f"({plain} is exported as {alias})")

    if others:
        header.append(f"({others} more match(es) elsewhere; showing the most likely)")

    return header + shown


_DEFINE = re.compile(r"^\s*#\s*define\s+(\w+)\s+(\w+)\s*$")


def elf_alias(root, name, exported):
    """Return the exported symbol a header #define maps name to, or None.

    Reads "#define name other" lines in .h and .in files under root and
    accepts only a target the binary actually exports (gmp does this:
    mpz_add is __gmpz_add).
    """

    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)

        for filename in sorted(files):
            if not filename.endswith((".h", ".in")):
                continue

            try:
                text = (Path(folder) / filename).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue

            for line in text.splitlines():
                match = _DEFINE.match(line)

                if match and match.group(1) == name and match.group(2) in exported:
                    return match.group(2)

    return None


_START = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def index_functions(root, names):
    """Return {name: (relative file, line)} for functions defined under root.

    Only definitions count (a "{" at column 0 before any ";"), files
    under tests folders are skipped, and the first definition wins.
    """

    root = Path(root)
    wanted = {base_name(name) for name in names}
    found = {}

    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in ("tests", "gnulib-tests"))

        for filename in sorted(files):
            if not filename.endswith(".c"):
                continue

            path = Path(folder) / filename

            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for index, depth in _top_level_lines(lines):
                line = lines[index]
                match = _START.search(line)

                if (
                    not depth
                    and
                    match
                    and match.group(1) in wanted
                    and match.group(1) not in found
                    and _body_end(lines, index) is not None
                ):
                    found[match.group(1)] = (
                        path.relative_to(root).as_posix(),
                        index + 1,
                    )

    return found


def source_files(path, say=lambda text: None):
    """Return ({file: [function names]}, root), or (None, message).

    The files are those of the source package that define functions
    this binary has, found by name.
    """

    with _cache_lock():
        return _source_files_locked(path, say)


def _source_files_locked(path, say):
    path = Path(path)

    if command_kind(path) != "elf":
        return None, "Not an ELF binary: --source reads ELF only"

    table = read_function_table(path)

    if not table:
        return None, "No function names in this binary (it has no .gnu_debugdata)"

    for root in local_source_roots():
        files = {}
        for name, (relative, _line) in index_functions(root, [e[2] for e in table]).items():
            files.setdefault(relative, []).append(name)
        if files:
            ordered = sorted(files, key=lambda f: (-len(files[f]), f))
            return {f: sorted(files[f]) for f in ordered}, root

    info = _query(path.resolve())

    if info is None:
        return None, _source_package_unavailable(path.resolve())

    try:
        root = ensure_source(info[0], info[1], say)
    except FileNotFoundError as error:
        return None, f"Source not available: {error}"
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return None, f"Could not fetch the source package: {error}"

    files = {}

    for name, (relative, _line) in index_functions(root, [e[2] for e in table]).items():
        files.setdefault(relative, []).append(name)

    ordered = sorted(files, key=lambda f: (-len(files[f]), f))

    return {f: sorted(files[f]) for f in ordered}, root


def file_lines(root, relative, max_lines=400):
    """Return a source file with line numbers, capped at max_lines."""

    root = Path(root).resolve()
    path = (root / relative).resolve()

    if root not in path.parents or not path.is_file():
        return ["Not a source file"]

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    shown = [f"{n:5d}  {line}" for n, line in enumerate(lines[:max_lines], 1)]

    if len(lines) > max_lines:
        shown.append(f"... and {len(lines) - max_lines} more lines")

    return shown


def files_lines(path, name=None, say=lambda text: None):
    """List the source files of a binary, or print one of them."""

    with _cache_lock():
        return _files_lines_locked(path, name, say)


def _files_lines_locked(path, name, say):
    files, root = source_files(path, say)

    if files is None:
        return [root]

    if name is None:
        lines = [f"{f} ({len(n)} function(s))" for f, n in files.items()]

        return lines + [
            "",
            "Read one with --source <file>, or a function with --source <function>.",
        ]

    matches = [f for f in files if f == name or f.endswith("/" + name)]

    if not matches:
        return [f"Not one of this binary's source files: {name[:60]}"] + list(files)[:10]

    return [matches[0]] + file_lines(root, matches[0])


def cached_source_files(path):
    """Return {file: [functions]} if the source package is already cached, else None.

    Never downloads.
    """

    with _cache_lock():
        return _cached_source_files_locked(path)


def _cached_source_files_locked(path):
    path = Path(path)

    if command_kind(path) != "elf":
        return None

    local_roots = local_source_roots()
    table = read_function_table(path) if local_roots else None
    if table:
        for local_root in local_roots:
            local_files = {}
            for name, (relative, _line) in index_functions(
                local_root, [entry[2] for entry in table]
            ).items():
                local_files.setdefault(relative, []).append(name)
            if local_files:
                return {
                    file: sorted(names)
                    for file, names in sorted(
                        local_files.items(), key=lambda item: (-len(item[1]), item[0])
                    )
                }

    info = _query(path.resolve())

    if info is None:
        return None

    root = cache_root() / info[1]

    if not (root / ".done").is_file():
        return None

    if table is None:
        table = read_function_table(path)
    files = {}

    for name, (relative, _line) in index_functions(root, [e[2] for e in table]).items():
        files.setdefault(relative, []).append(name)

    return {f: sorted(files[f]) for f in sorted(files, key=lambda f: (-len(files[f]), f))}
