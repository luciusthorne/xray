"""Debian source files for installed programs, from sources.debian.org.

Debian's debuginfod server sends debug information but not source, and
Debian builds record relative, prefix-mapped paths (./debian/build/src/...).
sources.debian.org serves every file of every Debian source package version
with Debian's patches applied, so the exact source a binary was built from
can be fetched one file at a time: the source package and version come from
dpkg, and the DWARF path is matched to the source tree by trying its
suffixes (an out-of-tree build directory is dropped that way).
"""

import posixpath
import re
import subprocess
from pathlib import Path

SOURCES = "https://sources.debian.org/data/main/{prefix}/{package}/{version}/{path}"  # the main archive
_MAX_FILE = 16 * 1024 * 1024
_TRIES = 8

_PACKAGES = {}
_MISSES = set()


def source_package(binary):
    """(source package, version) of the Debian package owning binary, or None."""

    binary = str(Path(binary).resolve())
    if binary in _PACKAGES:
        return _PACKAGES[binary]
    from xray.provenance import _dpkg_owner_lines, _usrmerge_aliases

    found = None
    owners = _dpkg_owner_lines(_usrmerge_aliases(binary))
    package = next(iter(owners.values()), None)
    if package:
        try:
            out = subprocess.run(
                ["dpkg-query", "-W", "-f", "${source:Package} ${source:Version}\n", "--", package],
                capture_output=True, text=True, errors="replace", check=False, timeout=30,
            ).stdout.split()
        except (OSError, subprocess.SubprocessError):
            out = []
        if len(out) == 2:
            found = (out[0], out[1])
    _PACKAGES[binary] = found
    return found


def _prefix(package):
    return package[:4] if package.startswith("lib") and len(package) > 3 else package[0]


def candidates(file):
    """Relative paths to try for a DWARF path, longest first.

    ./debian/build/src/./debian/build/src/tool_main.c -> debian/build/src/debian/build/src/tool_main.c,
    build/src/..., ..., src/tool_main.c, tool_main.c
    """

    path = posixpath.normpath(file)
    path = re.sub(r"^/build/reproducible-path/[^/]+/", "", path)
    path = re.sub(r"^/build/[^/]+/[^/]+-[0-9][^/]*/", "", path)
    path = path.lstrip("/")
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if ".." in parts:
        return []
    return ["/".join(parts[index:]) for index in range(len(parts))]


def _download(url):
    import urllib.request

    from xray import __version__

    request = urllib.request.Request(url, headers={"User-Agent": f"xray-trust/{__version__} (source viewer)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if "text/html" in response.headers.get("Content-Type", "") and not url.endswith((".html", ".htm")):
            raise OSError("not a file")  # a directory listing or an error page
        data = response.read(_MAX_FILE + 1)
    if len(data) > _MAX_FILE:
        raise OSError("file too large")
    return data


def source_file(binary, file, fetch=None):
    """Local copy of a source file of binary's Debian source package, or None."""

    found = source_package(binary)
    if found is None:
        return None
    package, version = found
    from xray.evidencestore import cache_dir

    root = cache_dir() / "debsrc" / f"{package}_{version}"
    fetch = fetch or _download
    tries = 0
    for relative in candidates(file):
        target = root / relative
        if target.is_file():
            return target
        url = SOURCES.format(prefix=_prefix(package), package=package, version=version, path=relative)
        if url in _MISSES:
            continue
        tries += 1
        try:
            data = fetch(url)
        except OSError:
            _MISSES.add(url)
            if tries >= _TRIES:
                break
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target
    return None
