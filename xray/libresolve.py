import os
import platform
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

STANDARD_DIRS = ("/lib64", "/usr/lib64", "/lib", "/usr/lib")

_ENTRY = re.compile(r"^\s*(\S+)\s+\([^)]*\)\s+=>\s+(\S+)\s*$")


def parse_ldconfig(text):
    """Return {library name: path} from "ldconfig -p" output.

    When a name is listed several times (other architectures), the
    first entry wins.
    """

    cache = {}

    for line in text.splitlines():
        match = _ENTRY.match(line)

        if match:
            cache.setdefault(match.group(1), match.group(2))

    return cache


def parse_ldconfig_entries(text):
    """Return {library name: [(flags, path), ...]} from "ldconfig -p" output."""

    entries = {}
    for line in text.splitlines():
        match = _ENTRY_FLAGS.match(line)
        if match:
            entries.setdefault(match.group(1), []).append((match.group(2), match.group(3)))
    return entries


_ENTRY_FLAGS = re.compile(r"^\s*(\S+)\s+\(([^)]*)\)\s+=>\s+(\S+)\s*$")


def ldconfig_entries():
    """Return every ldconfig cache entry with its flags, or {} if ldconfig can't run."""

    try:
        result = subprocess.run(
            ["ldconfig", "-p"], capture_output=True, text=True, errors="replace", check=False,
        )
    except OSError:
        return {}
    return parse_ldconfig_entries(result.stdout)


def ldconfig_cache():
    """Return the system library cache, or {} if ldconfig can't run."""

    try:
        result = subprocess.run(
            ["ldconfig", "-p"],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return {}

    return parse_ldconfig(result.stdout)


def find_library(name, cache=None, dirs=STANDARD_DIRS):
    """Return the resolved file of a shared library, or None.

    Looks in the ldconfig cache first, then in the standard
    directories. RPATH and RUNPATH entries are not considered.
    """

    if cache is None:
        cache = ldconfig_cache()

    candidates = []

    if name in cache:
        candidates.append(Path(cache[name]))

    candidates.extend(Path(directory) / name for directory in dirs)

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    return None


@dataclass(frozen=True)
class Resolution:
    """How the dynamic loader would find one shared library.

    method is "path" (the name holds a slash), "rpath", "LD_LIBRARY_PATH",
    "runpath", "ldconfig" or "default"; directory is the search
    directory that held it. path is None when nothing matched, and
    searched lists the directories tried, in order.
    """

    path: Path | None
    method: str | None = None
    directory: str | None = None
    searched: tuple = ()


def expand_tokens(entry, origin, elf_class=64):
    """Expand $ORIGIN, $LIB and $PLATFORM in one search path entry."""

    lib = "lib64" if elf_class == 64 and Path("/usr/lib64").is_dir() and not Path("/usr/lib64").is_symlink() else "lib"
    values = {"ORIGIN": str(origin), "LIB": lib, "PLATFORM": platform.machine()}
    for name, value in values.items():
        entry = entry.replace("${" + name + "}", value).replace("$" + name, value)
    return entry


def _class_matches(flags, elf_class):
    wide = "64" in flags
    return wide if elf_class == 64 else not wide


def resolve_library(
    soname,
    origin,
    rpath=(),
    runpath=(),
    inherited_rpath=(),
    elf_class=64,
    nodeflib=False,
    entries=None,
    environ=None,
    secure=False,
):
    """Resolve a DT_NEEDED name the way glibc's ld.so does (see ld.so(8)).

    Order: a name with a slash is a path; else DT_RPATH of the object
    and of the objects that loaded it (only when the object has no
    DT_RUNPATH), LD_LIBRARY_PATH (ignored for setuid programs), DT_RUNPATH,
    the ldconfig cache and the default directories (both skipped with
    -z nodefaultlib). Cache entries for the other word size are skipped.
    """

    if "/" in soname:
        candidate = Path(soname) if Path(soname).is_absolute() else Path(origin) / soname
        return Resolution(candidate.resolve() if candidate.is_file() else None, "path", str(candidate.parent))

    environ = os.environ if environ is None else environ
    searched = []

    def look(method, directories):
        for directory in directories:
            directory = expand_tokens(directory, origin, elf_class) if directory else "."
            searched.append(directory)
            candidate = Path(directory) / soname
            if candidate.is_file():
                return Resolution(candidate.resolve(), method, directory, tuple(searched))
        return None

    if not runpath:
        found = look("rpath", [*rpath, *inherited_rpath])
        if found:
            return found
    library_path = environ.get("LD_LIBRARY_PATH")
    if library_path and not secure:
        found = look("LD_LIBRARY_PATH", library_path.replace(";", ":").split(":"))
        if found:
            return found
    found = look("runpath", runpath)
    if found:
        return found
    if nodeflib:
        return Resolution(None, None, None, tuple(searched))

    if entries is None:
        entries = ldconfig_entries()
    for flags, cached in entries.get(soname, ()):
        if _class_matches(flags, elf_class) and Path(cached).is_file():
            return Resolution(Path(cached).resolve(), "ldconfig", str(Path(cached).parent), tuple(searched))

    defaults = ("/lib64", "/usr/lib64") if elf_class == 64 else ("/lib32", "/usr/lib32", "/lib", "/usr/lib")
    if elf_class == 64:
        defaults += ("/lib", "/usr/lib")
    found = look("default", defaults)
    return found or Resolution(None, None, None, tuple(searched))


def search_path_risks(entries, origin, kind, elf_class=64, owner_uid=0):
    """Describe search path entries another user could use to plant a library.

    An empty or relative entry is searched relative to the current
    directory of whoever runs the program. A directory, or the nearest
    existing parent of a missing one, that is writable by other users
    (a sticky bit does not stop anyone adding a file), or owned by someone other than root and
    the program's owner, also lets someone else place a library there.
    Returns a list of messages; an empty list proves nothing about safety.
    """

    risks = []
    for raw in entries:
        if raw == "":
            risks.append(f"empty {kind} entry: libraries are searched in the current directory")
            continue
        expanded = expand_tokens(raw, origin, elf_class)
        if not expanded.startswith("/"):
            risks.append(f"relative {kind} entry `{raw}`: resolved against the current directory")
            continue
        directory = Path(expanded)
        missing = not directory.exists()
        while not directory.exists() and directory != directory.parent:
            directory = directory.parent
        try:
            info = directory.stat()
        except OSError:
            continue
        writable = info.st_mode & stat.S_IWOTH  # the sticky bit does not stop new files
        stranger = info.st_uid not in (0, owner_uid)
        if writable or stranger:
            owner = "writable by other users" if writable else f"owned by uid {info.st_uid}"
            where = f"does not exist, and its parent {directory} is" if missing else "is"
            risks.append(f"{kind} entry `{raw}` {where} {owner}")
    return risks
