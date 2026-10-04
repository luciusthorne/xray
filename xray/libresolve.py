import re
import subprocess
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
