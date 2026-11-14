"""Read Electron ``.asar`` archives without unpacking them.

An asar file is a Chromium "pickle" header followed by the file data:

    uint32  4                     size of the next field
    uint32  header_size           size of the header pickle
    uint32  payload_size          header pickle payload
    uint32  json_size             length of the JSON index
    bytes   json                  {"files": {name: entry, ...}}
    ...                           file data starts at 8 + header_size

A file entry has ``size`` and ``offset`` (a decimal string, relative to
the data start), and optionally ``unpacked`` (the file lives in
``<archive>.unpacked/`` next to it), ``executable`` and ``integrity``
(SHA-256 of the file). A directory entry has ``files``; a symlink has
``link``.

Member names come from the archive, so they are untrusted: names with
``..``, empty or absolute parts, or NUL are refused, and files are only
written below XRAY's cache directory.
"""

import hashlib
import json
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath

MAX_INDEX = 64 * 1024 * 1024  # a JSON index larger than this is not an asar we can trust


class AsarError(ValueError):
    pass


@dataclass(frozen=True)
class Member:
    name: str          # path inside the archive, with "/" separators
    size: int
    offset: int | None  # None for unpacked files
    unpacked: bool
    executable: bool
    sha256: str | None


def _safe_name(name):
    parts = PurePosixPath(name).parts
    if not parts or name.startswith("/") or "\x00" in name:
        return False
    return all(part not in ("", ".", "..") and "/" not in part and "\\" not in part for part in parts)


def is_asar(path):
    try:
        with open(path, "rb") as handle:
            start = handle.read(16)
    except OSError:
        return False
    if len(start) < 16:
        return False
    first, header, payload, length = struct.unpack("<4I", start)
    return first == 4 and header == payload + 4 and length <= payload <= MAX_INDEX and start.startswith(b"\x04\0\0\0")


def _signature(path):
    info = Path(path).stat()
    return (str(Path(path).resolve()), info.st_size, info.st_mtime_ns, info.st_ino)


def members(path):
    """Every regular file in the archive, in index order."""

    return _members(*_signature(path))


@lru_cache(maxsize=16)
def _members(real, size, _mtime, _inode):
    with open(real, "rb") as handle:
        start = handle.read(16)
        if len(start) < 16:
            raise AsarError(f"{real} is too short to be an asar archive")
        first, header, payload, length = struct.unpack("<4I", start)
        if first != 4 or header != payload + 4 or not length <= payload <= MAX_INDEX or 8 + header > size:
            raise AsarError(f"{real} does not start with an asar header")
        try:
            index = json.loads(handle.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AsarError(f"{real}: the asar index is not valid JSON ({error})") from error
    base = 8 + header
    found = []

    def walk(tree, prefix):
        if not isinstance(tree, dict):
            raise AsarError(f"{real}: malformed asar index")
        for key, entry in tree.items():
            name = f"{prefix}{key}"
            if not isinstance(entry, dict) or not _safe_name(name):
                continue  # refused: unsafe or malformed name
            if "files" in entry:
                walk(entry["files"], name + "/")
                continue
            if "link" in entry:
                continue
            try:
                member_size = int(entry.get("size", 0))
                unpacked = bool(entry.get("unpacked"))
                offset = None if unpacked else base + int(entry["offset"])
            except (KeyError, TypeError, ValueError):
                continue
            if member_size < 0 or (offset is not None and offset + member_size > size):
                continue
            integrity = entry.get("integrity") or {}
            digest = integrity.get("hash") if str(integrity.get("algorithm", "")).upper() == "SHA256" else None
            found.append(Member(name, member_size, offset, unpacked, bool(entry.get("executable")), digest))

    walk(index.get("files", {}), "")
    return tuple(found)


def member(path, name):
    for item in members(path):
        if item.name == name:
            return item
    return None


def read(path, name, limit=None):
    """Bytes of one member (from the archive, or from <archive>.unpacked/)."""

    item = member(path, name) if isinstance(name, str) else name
    if item is None:
        raise AsarError(f"{name} is not in {path}")
    size = item.size if limit is None else min(item.size, limit)
    if item.unpacked:
        outside = Path(str(path) + ".unpacked") / item.name
        with open(outside, "rb") as handle:
            return handle.read(size)
    with open(path, "rb") as handle:
        handle.seek(item.offset)
        return handle.read(size)


def verified(path, item):
    """True when the member matches the SHA-256 in the index, False when not, None without one."""

    if item.sha256 is None:
        return None
    try:
        return hashlib.sha256(read(path, item)).hexdigest() == item.sha256
    except OSError:
        return False


def extract(path, name):
    """Write one member below the XRAY cache and return that path.

    The copy keeps the member's path inside a directory named after the
    archive's identity, so tools that work on real files (the JavaScript
    parser) can read it. Unpacked members are returned where they are.
    """

    from .evidencestore import cache_dir

    item = member(path, name) if isinstance(name, str) else name
    if item is None:
        raise AsarError(f"{name} is not in {path}")
    if item.unpacked:
        return Path(str(path) + ".unpacked") / item.name
    key = hashlib.sha256(repr(_signature(path)).encode()).hexdigest()[:20]
    root = (cache_dir() / "asar" / key).resolve()
    target = (root / item.name).resolve()
    if root not in target.parents:
        raise AsarError(f"refusing to write {item.name} outside the cache")
    if target.is_file() and target.stat().st_size == item.size:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    partial.write_bytes(read(path, item))
    partial.replace(target)
    return target
