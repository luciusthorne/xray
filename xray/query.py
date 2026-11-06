"""Query XRAY's data with SQL (read-only).

``xray query SQL`` runs against the scan store (``xray scan``), opened
read-only, with these tables:

    programs(command, root, epoch, scanned, summary)   one row per scanned program
    reach(command, node, kind, label)                   everything each program reaches
    owners(path, manager, owner)                        package that owns each file
    files(path, signature, sha256, kind, seen)          files read into the store

``xray query --log [FILE] SQL`` loads a capability log into memory instead:

    archives(seq, package, version, arch, archive, sha256)
    files(package, version, path, kind, sha256, ifuncs, constructors, setuid, soname)
    needs(package, version, path, library)
    calls(package, version, path, class, symbol)        imported calls by capability class
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

EXAMPLES = {
    "programs reaching OpenSSL's libssl":
        "SELECT DISTINCT command FROM reach WHERE label LIKE 'libssl.so%' ORDER BY command",
    "packages most programs depend on":
        "SELECT owners.owner, COUNT(DISTINCT reach.command) AS programs FROM reach "
        "JOIN owners ON owners.path = reach.node GROUP BY owners.owner ORDER BY programs DESC LIMIT 10",
    "scripts that run curl or wget":
        "SELECT DISTINCT command FROM reach WHERE kind = 'command' AND label IN ('curl', 'wget')",
    "(--log) libraries that call system() or popen()":
        "SELECT DISTINCT package, path, symbol FROM calls WHERE class = 'shell' AND path LIKE '%.so%'",
    "(--log) library files with IFUNC resolvers that link the dynamic loader":
        "SELECT f.package, f.version, f.path FROM files f JOIN needs n USING (package, version, path) "
        "WHERE f.ifuncs > 0 AND n.library LIKE 'ld-linux%'",
    "(--log) setuid files":
        "SELECT package, version, path FROM files WHERE setuid = 1",
}


def open_store(path):
    uri = f"file:{Path(path).resolve()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def load_log(path):
    """An in-memory database of a capability log's profiles."""

    from . import caplog

    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE archives(seq, package, version, arch, archive, sha256);
        CREATE TABLE files(package, version, path, kind, sha256, ifuncs, constructors, setuid, soname);
        CREATE TABLE needs(package, version, path, library);
        CREATE TABLE calls(package, version, path, class, symbol);
    """)
    for entry in caplog.read_log(path):
        package, version = entry.get("package"), entry.get("version")
        db.execute("INSERT INTO archives VALUES (?,?,?,?,?,?)", (entry.get("seq"), package, version,
                   entry.get("arch"), entry.get("archive"), entry.get("archive_sha256")))
        for file, profile in (entry.get("files") or {}).items():
            db.execute("INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?)", (
                package, version, file, profile.get("kind"), profile.get("sha256"), profile.get("ifuncs") or 0,
                profile.get("constructors") or 0, int(bool(profile.get("setuid"))), profile.get("soname")))
            db.executemany("INSERT INTO needs VALUES (?,?,?,?)",
                           [(package, version, file, library) for library in profile.get("needed") or []])
            db.executemany("INSERT INTO calls VALUES (?,?,?,?,?)",
                           [(package, version, file, cls, symbol)
                            for cls, symbols in (profile.get("classes") or {}).items() for symbol in symbols])
    db.commit()
    return db


def run(db, sql, limit=None):
    """(column names, rows). Only SELECT and WITH statements are accepted."""

    statement = sql.strip().rstrip(";")
    if not statement.lower().startswith(("select", "with")):
        raise ValueError("only SELECT (or WITH ... SELECT) queries are allowed")
    if ";" in statement:
        raise ValueError("one statement at a time")
    cursor = db.execute(statement)
    names = [column[0] for column in cursor.description or ()]
    rows = cursor.fetchmany(limit) if limit else cursor.fetchall()
    return names, rows


def table_lines(names, rows):
    if not names:
        return ["(no columns)"]
    text = [[("" if value is None else str(value)) for value in row] for row in rows]
    widths = [min(60, max([len(name)] + [len(row[index]) for row in text])) for index, name in enumerate(names)]
    lines = ["  ".join(name.ljust(width) for name, width in zip(names, widths))]
    lines.append("  ".join("-" * width for width in widths))
    for row in text:
        lines.append("  ".join(value[:width].ljust(width) for value, width in zip(row, widths)).rstrip())
    lines.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''})")
    return lines


def json_rows(names, rows):
    return json.dumps({"schema_version": 1, "columns": names,
                       "rows": [dict(zip(names, row)) for row in rows]}, indent=2)
