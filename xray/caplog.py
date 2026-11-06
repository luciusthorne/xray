"""A tamper-evident capability transparency log over package versions.

Each line of the log (JSON Lines) records one package archive: its name,
version and SHA-256, and the capability profile of every executable,
library and script in it. Every entry holds the hash of the entry before
it, so changing or dropping any past entry breaks every later hash:
publishing the newest hash (the head) pins the whole history.

From the log, ``xray log history NAME`` shows what each new version of a
package gained, and ``xray log gains`` lists every gain across the log.
"""

from __future__ import annotations

import datetime
import hashlib
import itertools
import json
import os
import shutil
import subprocess
from functools import cmp_to_key
from pathlib import Path

from .drift import drift, opened, profiles
from .profile import sha256

LOG_VERSION = 1
GENESIS = "0" * 64


def default_log_path():
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(os.environ.get("XRAY_LOG") or Path(base) / "xray" / "capability-log.jsonl")


def entry_hash(entry):
    body = {key: value for key, value in entry.items() if key != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_log(path):
    path = Path(path)
    if not path.exists():
        return []
    entries = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    entries.append({"seq": None, "broken_line": number})
    return entries


def verify(entries):
    """Return (ok, head, message). Checks every hash and every link to the entry before."""

    previous = GENESIS
    for index, entry in enumerate(entries):
        if "broken_line" in entry:
            return False, None, f"line {entry['broken_line']} is not valid JSON"
        if entry.get("seq") != index:
            return False, None, f"entry {index} has sequence number {entry.get('seq')}"
        if entry.get("prev") != previous:
            return False, None, f"entry {index} ({entry.get('package')} {entry.get('version')}) does not link to the entry before it"
        if entry_hash(entry) != entry.get("hash"):
            return False, None, f"entry {index} ({entry.get('package')} {entry.get('version')}) was changed after it was written"
        previous = entry["hash"]
    return True, previous, f"{len(entries)} entries, all hashes and links intact"


def add_archives(log_path, archives, progress=None):
    """Append one entry per new archive (skipping archives already logged). Returns added entries."""

    log_path = Path(log_path)
    entries = read_log(log_path)
    ok, head, message = verify(entries)
    if not ok:
        raise ValueError(f"the log does not verify, refusing to append: {message}")
    known = {entry["archive_sha256"] for entry in entries}
    log_path.parent.mkdir(parents=True, exist_ok=True)
    added = []
    with open(log_path, "a", encoding="utf-8") as handle:
        for number, archive in enumerate(archives, 1):
            digest = sha256(archive)
            if digest in known:
                continue
            if progress:
                progress(number, len(archives), archive)
            with opened(archive) as (_, _, files, meta):
                found = profiles(files)
            entry = {
                "log_version": LOG_VERSION,
                "seq": len(entries) + len(added),
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "package": meta.get("pkgname") or Path(archive).name,
                "version": meta.get("pkgver"),
                "arch": meta.get("arch"),
                "packager": meta.get("packager"),
                "archive": Path(archive).name,
                "archive_sha256": digest,
                "files": found,
                "prev": head,
            }
            entry["hash"] = entry_hash(entry)
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            head = entry["hash"]
            known.add(digest)
            added.append(entry)
    return added


def vercmp(left, right):
    if left == right:
        return 0
    if shutil.which("vercmp"):
        done = subprocess.run(["vercmp", left or "", right or ""], capture_output=True, text=True, check=False)
        try:
            return int(done.stdout.strip())
        except ValueError:
            pass
    return (left > right) - (left < right)


def versions_of(entries, package):
    found = [entry for entry in entries if entry.get("package") == package]
    return sorted(found, key=cmp_to_key(lambda a, b: vercmp(a.get("version"), b.get("version"))))


def history(entries, package):
    """[(older entry, newer entry, drift report)] for consecutive versions of a package."""

    ordered = versions_of(entries, package)
    return [(older, newer, drift(older["files"], newer["files"])) for older, newer in itertools.pairwise(ordered)]


def all_gains(entries):
    out = []
    for package in sorted({entry.get("package") for entry in entries}):
        for older, newer, report in history(entries, package):
            for gain in report["gains"]:
                out.append({"package": package, "from": older.get("version"), "to": newer.get("version"), **gain})
    return out


def cached_archives(directory="/var/cache/pacman/pkg"):
    directory = Path(directory)
    if not directory.is_dir():
        return []
    return sorted(
        str(path) for path in directory.iterdir()
        if path.name.endswith((".pkg.tar.zst", ".pkg.tar.xz")) and path.is_file()
    )
