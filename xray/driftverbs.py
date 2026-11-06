"""``xray drift``, ``xray whatif`` and ``xray log``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import CLIError

DRIFT_USAGE = "usage: xray drift OLD NEW [--json] [--fail-on-gain]   (file, directory, package archive or installed:NAME)"
WHATIF_USAGE = """usage: xray whatif remove PACKAGE [--json]
       xray whatif upgrade ARCHIVE [--json]"""
LOG_USAGE = """usage: xray log add ARCHIVE... | --from-cache [DIR]   [--log FILE]
       xray log verify [--log FILE]
       xray log history PACKAGE [--log FILE] [--json]
       xray log gains [--log FILE] [--json]"""


def _parse(parser, argv):
    try:
        return parser.parse_args(argv)
    except SystemExit as stop:
        if stop.code in (0, None):
            raise _Help() from None
        raise CLIError(f"usage: {parser.format_usage().strip()}") from None


class _Help(Exception):
    pass


def _guard(function):
    def wrapper(argv):
        try:
            return function(argv)
        except _Help:
            return 0
    return wrapper


# -- drift ------------------------------------------------------------------------

@_guard
def run_drift(argv):
    from .drift import drift, drift_lines, opened, profiles

    parser = argparse.ArgumentParser(prog="xray drift", description=DRIFT_USAGE)
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-gain", action="store_true", help="exit 1 when any capability was gained")
    options = _parse(parser, argv)
    with opened(options.old) as (old_label, _, old_files, old_meta), \
            opened(options.new) as (new_label, _, new_files, new_meta):
        report = drift(profiles(old_files), profiles(new_files))
    if options.json:
        print(json.dumps({"schema_version": 1, "old": {"source": old_label, **old_meta},
                          "new": {"source": new_label, **new_meta}, **report}, indent=2))
    else:
        print("\n".join(drift_lines(old_label, new_label, report, old_meta, new_meta)))
    return 1 if options.fail_on_gain and report["gains"] else 0


# -- whatif -----------------------------------------------------------------------

@_guard
def run_whatif(argv):
    if not argv or argv[0] not in ("remove", "upgrade"):
        raise CLIError(WHATIF_USAGE)
    parser = argparse.ArgumentParser(prog=f"xray whatif {argv[0]}")
    parser.add_argument("target")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--store", metavar="FILE")
    options = _parse(parser, argv[1:])
    if argv[0] == "remove":
        return _whatif_remove(options)
    return _whatif_upgrade(options)


def _reach(target, store_path):
    from .scan import reach_programs

    return reach_programs(target, store_path)


def _whatif_remove(options):
    from .drift import installed_files

    found, total, stale = _reach(options.target, options.store)
    files = installed_files(options.target, everything=True)
    if options.json:
        print(json.dumps({"schema_version": 1, "package": options.target, "scanned_programs": total, "stale": stale,
                          "programs": [{"command": command, "basis": basis, "steps": steps}
                                       for command, basis, steps in found]}, indent=2))
        return 0
    lines = []
    if stale:
        lines.append("Note: programs were installed or removed since the last scan; run `xray scan` to refresh.")
    own = {Path(path).name for path in files}
    outside = [item for item in found if item[0] not in own]
    lines.append(f"Removing {options.target} would affect {len(outside)} of {total} scanned programs from other packages"
                 + (f" (and its own {len(found) - len(outside)})" if len(found) != len(outside) else ""))
    for command, basis, steps in outside[:40]:
        lines.append(f"  {command:<24} [{basis}]  {steps}")
    if len(outside) > 40:
        lines.append(f"  … {len(outside) - 40} more (--json)")
    if not outside:
        lines.append("  nothing else reaches it statically (programs may still use it at run time).")
    print("\n".join(lines))
    return 0


def _whatif_upgrade(options):
    from .drift import drift, drift_lines, opened, profiles

    with opened(options.target) as (label, _, new_files, meta):
        name = meta.get("pkgname")
        if not name:
            raise CLIError("the archive has no .PKGINFO: cannot tell which installed package it upgrades")
        new = profiles(new_files)
    with opened(f"installed:{name}") as (old_label, _, old_files, _meta):
        old = profiles(old_files)
    report = drift(old, new)
    version = _installed_version(name)
    old_meta = {"pkgname": name, "pkgver": version or "installed"}
    exposed = {}
    for gain in report["gains"]:
        target = "/" + gain["path"]
        if target not in exposed and Path(target).exists():
            try:
                exposed[target] = _reach(target, options.store)[0]
            except CLIError:
                exposed = {}  # no scan yet: drift alone
                break
    if options.json:
        print(json.dumps({"schema_version": 1, "package": name, "from": version, "to": meta.get("pkgver"), **report,
                          "exposed": {path: [command for command, _, _ in found] for path, found in exposed.items()}},
                         indent=2))
        return 0
    lines = drift_lines(old_label, label, report, old_meta, meta)
    if exposed:
        lines.append("")
        lines.append("Programs that reach the files that gained capabilities")
        for path, found in exposed.items():
            names = [command for command, _, _ in found]
            lines.append(f"  {path}: {len(names)} program(s)" + (f" — {', '.join(names[:8])}" + (" …" if len(names) > 8 else "") if names else ""))
    print("\n".join(lines))
    return 1 if report["gains"] else 0


def _installed_version(name):
    import shutil
    import subprocess

    if shutil.which("pacman"):
        done = subprocess.run(["pacman", "-Q", name], capture_output=True, text=True, check=False)
        if done.returncode == 0:
            return done.stdout.split()[-1]
    return None


# -- log --------------------------------------------------------------------------

@_guard
def run_log(argv):
    from . import caplog

    if not argv or argv[0] not in ("add", "verify", "history", "gains"):
        raise CLIError(LOG_USAGE)
    command = argv[0]
    parser = argparse.ArgumentParser(prog=f"xray log {command}")
    if command == "add":
        parser.add_argument("archives", nargs="*")
        parser.add_argument("--from-cache", nargs="?", const="/var/cache/pacman/pkg", metavar="DIR")
        parser.add_argument("--limit", type=int, metavar="N", help="add at most N archives")
    if command == "history":
        parser.add_argument("package")
    if command in ("history", "gains"):
        parser.add_argument("--json", action="store_true")
    parser.add_argument("--log", metavar="FILE", help="log file (default ~/.local/share/xray/capability-log.jsonl)")
    options = _parse(parser, argv[1:])
    log_path = Path(options.log) if options.log else caplog.default_log_path()

    if command == "add":
        archives = list(options.archives)
        if options.from_cache:
            archives += caplog.cached_archives(options.from_cache)
        if options.limit:
            archives = archives[:options.limit]
        if not archives:
            raise CLIError("no archives given (pass files or --from-cache)")

        def progress(number, total, archive):
            if sys.stderr.isatty():
                print(f"\rlogging {number}/{total} {Path(archive).name[:50]:<50}", end="", file=sys.stderr, flush=True)

        try:
            added = caplog.add_archives(log_path, archives, progress)
        except ValueError as error:
            raise CLIError(str(error)) from None
        if sys.stderr.isatty():
            print("\r" + " " * 70 + "\r", end="", file=sys.stderr)
        _, head, _ = caplog.verify(caplog.read_log(log_path))
        print(f"added {len(added)} entries ({len(archives) - len(added)} already logged) to {log_path}")
        print(f"head {head}   (publish this hash to pin the log)")
        return 0

    entries = caplog.read_log(log_path)
    if command == "verify":
        ok, head, message = caplog.verify(entries)
        print(("OK: " if ok else "BROKEN: ") + message)
        if ok:
            print(f"head {head}")
        return 0 if ok else 1

    if command == "history":
        steps = caplog.history(entries, options.package)
        versions = caplog.versions_of(entries, options.package)
        if options.json:
            print(json.dumps({"schema_version": 1, "package": options.package,
                              "versions": [entry.get("version") for entry in versions],
                              "steps": [{"from": a.get("version"), "to": b.get("version"), **report}
                                        for a, b, report in steps]}, indent=2))
            return 0
        if not versions:
            raise CLIError(f"{options.package} is not in the log")
        lines = [f"{options.package}: {len(versions)} version(s) in the log: "
                 + ", ".join(entry.get("version") or "?" for entry in versions)]
        for older, newer, report in steps:
            lines.append("")
            lines.append(f"{older.get('version')} -> {newer.get('version')}: "
                         f"{len(report['gains'])} gained, {len(report['changed'])} files changed, "
                         f"{len(report['added'])} added, {len(report['removed'])} removed")
            for gain in report["gains"]:
                lines.append(f"  + {gain['path']}: {gain['detail']}")
        print("\n".join(lines))
        return 0

    gains = caplog.all_gains(entries)
    if options.json:
        print(json.dumps({"schema_version": 1, "gains": gains}, indent=2))
        return 0
    packages = {entry.get("package") for entry in entries}
    multi = sum(1 for name in packages if len(caplog.versions_of(entries, name)) > 1)
    lines = [f"{len(entries)} archives of {len(packages)} packages in the log; {multi} packages have more than one version",
             f"{len(gains)} capability gains between consecutive versions", ""]
    for gain in gains:
        lines.append(f"  {gain['package']} {gain['from']} -> {gain['to']}  {gain['path']}: {gain['detail']}")
    print("\n".join(lines))
    return 0
