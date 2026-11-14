"""A machine-wide store of evidence: what each file reaches, cached by content.

``xray scan`` reads every command on PATH into the evidence graph. What
one file reaches (its local facts) is stored with the file's size,
modification time and inode, plus a SHA-256 of its content, so later
scans and queries only re-read files that changed. Facts also depend on
the machine (PATH lookups, the ldconfig cache), so every entry carries a
machine epoch: a hash of PATH, the PATH directories' modification times
and /etc/ld.so.cache. Installing or removing a program changes the
epoch, and stale facts are read again.

The store also keeps an index of each scanned program's graph (the
nodes it reaches and the packages that own them) for ``xray reach``.
It lives in $XDG_CACHE_HOME/xray (~/.cache/xray), or $XRAY_CACHE_DIR.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

FACTS_VERSION = 7  # bump when the shape or meaning of stored facts changes


def cache_dir():
    explicit = os.environ.get("XRAY_CACHE_DIR")
    if explicit:
        return Path(explicit)
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "xray"


def default_store_path():
    return cache_dir() / f"evidence-v{FACTS_VERSION}.sqlite"


def _signature(path):
    info = os.stat(path)
    return f"{info.st_size}:{info.st_mtime_ns}:{info.st_ctime_ns}:{info.st_ino}"


def file_sha256(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def path_dirs(environ=None):
    environ = os.environ if environ is None else environ
    seen = []
    for entry in environ.get("PATH", "").split(":"):
        if entry and entry not in seen and Path(entry).is_dir():
            seen.append(entry)
    return seen


def machine_epoch(environ=None):
    """A hash of the machine state that command and library lookups depend on."""

    from . import __version__

    environ = os.environ if environ is None else environ
    parts = [__version__, str(FACTS_VERSION), environ.get("PATH", ""), environ.get("LD_LIBRARY_PATH", "")]
    for directory in [*path_dirs(environ), "/etc/ld.so.cache"]:
        try:
            parts.append(f"{directory}:{os.stat(directory).st_mtime_ns}")
        except OSError:
            parts.append(f"{directory}:-")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts (
    path TEXT, inherited TEXT, signature TEXT, epoch TEXT, data TEXT,
    PRIMARY KEY (path, inherited)
);
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY, signature TEXT, sha256 TEXT, kind TEXT, seen REAL
);
CREATE TABLE IF NOT EXISTS owners (path TEXT PRIMARY KEY, manager TEXT, owner TEXT);
CREATE TABLE IF NOT EXISTS programs (
    command TEXT PRIMARY KEY, root TEXT, epoch TEXT, scanned REAL, summary TEXT
);
CREATE TABLE IF NOT EXISTS reach (command TEXT, node TEXT, kind TEXT, label TEXT);
CREATE INDEX IF NOT EXISTS reach_node ON reach (node);
CREATE INDEX IF NOT EXISTS reach_command ON reach (command);
CREATE INDEX IF NOT EXISTS reach_label ON reach (label);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


class EvidenceStore:
    """Per-file evidence facts and the scan index, in one SQLite file."""

    def __init__(self, path=None, epoch=None):
        self.path = Path(path) if path else default_store_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.executescript(_SCHEMA)
        self.epoch = epoch or machine_epoch()
        self.hits = 0
        self.misses = 0

    def close(self):
        self.db.commit()
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # -- per-file facts ----------------------------------------------------
    def get(self, path, inherited=()):
        try:
            signature = _signature(path)
        except OSError:
            return None
        row = self.db.execute(
            "SELECT data FROM facts WHERE path = ? AND inherited = ? AND signature = ? AND epoch = ?",
            (path, ":".join(inherited), signature, self.epoch),
        ).fetchone()
        if row is None:
            self.misses += 1
            return None
        self.hits += 1
        return json.loads(row[0])

    def put(self, path, inherited, facts):
        try:
            signature = _signature(path)
        except OSError:
            return
        self.db.execute(
            "INSERT OR REPLACE INTO facts VALUES (?, ?, ?, ?, ?)",
            (path, ":".join(inherited), signature, self.epoch, json.dumps(facts)),
        )
        known = self.db.execute("SELECT signature FROM files WHERE path = ?", (path,)).fetchone()
        if known is None or known[0] != signature:
            try:
                digest = file_sha256(path)
            except OSError:
                digest = None
            self.db.execute(
                "INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
                (path, signature, digest, None, time.time()),
            )

    def sha256(self, path):
        row = self.db.execute("SELECT sha256 FROM files WHERE path = ?", (path,)).fetchone()
        return row[0] if row else None

    # -- package owners ------------------------------------------------------
    def set_owners(self, owners):
        self.db.executemany(
            "INSERT OR REPLACE INTO owners VALUES (?, ?, ?)",
            [(path, manager, owner) for path, (manager, owner) in owners.items()],
        )

    def owners(self):
        return {path: (manager, owner) for path, manager, owner in self.db.execute("SELECT * FROM owners")}

    # -- the scan index --------------------------------------------------------
    def index_program(self, command, graph, summary):
        self.db.execute("DELETE FROM reach WHERE command = ?", (command,))
        self.db.executemany(
            "INSERT INTO reach VALUES (?, ?, ?, ?)",
            [(command, node.id, node.kind, node.label) for node in graph.nodes.values() if node.id != graph.root],
        )
        self.db.execute(
            "INSERT OR REPLACE INTO programs VALUES (?, ?, ?, ?, ?)",
            (command, graph.root, self.epoch, time.time(), json.dumps(summary)),
        )

    def forget_programs(self, keep):
        keep = set(keep)
        gone = [row[0] for row in self.db.execute("SELECT command FROM programs") if row[0] not in keep]
        for command in gone:
            self.db.execute("DELETE FROM programs WHERE command = ?", (command,))
            self.db.execute("DELETE FROM reach WHERE command = ?", (command,))

    def programs(self):
        return {
            command: {"root": root, "epoch": epoch, "scanned": scanned, **json.loads(summary)}
            for command, root, epoch, scanned, summary in self.db.execute("SELECT * FROM programs")
        }

    def reaching(self, query):
        """Commands whose indexed graph holds a node matching query (as EvidenceGraph.find)."""

        resolved = str(Path(query).expanduser().resolve()) if "/" in query else None
        rows = self.db.execute(
            "SELECT DISTINCT command FROM reach WHERE node = ? OR node = ? OR label = ? "
            "OR (kind = 'package' AND (label = ? OR label LIKE ?))",
            (query, resolved or query, query, query, query + " %"),
        ).fetchall()
        if not rows and "/" not in query:
            rows = self.db.execute(
                "SELECT DISTINCT command FROM reach WHERE kind != 'package' AND (label LIKE ? OR label LIKE ?)",
                (query + ".%", query + "-%"),
            ).fetchall()
        return sorted(row[0] for row in rows)

    def set_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, json.dumps(value)))

    def meta(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default
