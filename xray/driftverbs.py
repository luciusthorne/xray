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
    parser.add_argument("--explain", action="store_true",
                        help="find the functions and source lines behind each new call class (uses debuginfod)")
    options = _parse(parser, argv)
    with opened(options.old) as (old_label, _, old_files, old_meta), \
            opened(options.new) as (new_label, _, new_files, new_meta):
        new_profiles = profiles(new_files)
        report = drift(profiles(old_files), new_profiles)
        if options.explain:
            _explain_gains(report, new_files, new_profiles)
    if options.json:
        print(json.dumps({"schema_version": 1, "old": {"source": old_label, **old_meta},
                          "new": {"source": new_label, **new_meta}, **report}, indent=2))
    else:
        print("\n".join(drift_lines(old_label, new_label, report, old_meta, new_meta)))
        for item in report.get("explained", []):
            print(f"\nWhy {item['path']} {item['detail']}")
            print(f"  line information: {item['how']}")
            for site in item["sites"] or []:
                print(f"  {site['symbol']:<10} in {site['function'] or 'unknown function'}"
                      f"  ({site['location'] or 'source line unknown'})")
            if not item["sites"]:
                print("  no direct calls found (reached through a function pointer or dlsym?)")
    return 1 if options.fail_on_gain and report["gains"] else 0


def _explain_gains(report, files, new_profiles):
    """Attach call sites with function and source line to every gained call class in an ELF file."""

    from .explain import explain

    report["explained"] = []
    for gain in report["gains"]:
        if not gain["field"].startswith("class:") or new_profiles.get(gain["path"], {}).get("kind") != "elf":
            continue
        symbols = [name.strip() for name in gain["detail"].split(":", 1)[1].split(",")]
        sites, how = explain(files[gain["path"]], symbols)
        report["explained"].append({
            "path": gain["path"], "detail": gain["detail"], "how": how,
            "sites": [{"symbol": site.symbol, "address": site.address, "function": site.function,
                       "location": site.location} for site in sites],
        })


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


@_guard
def run_compare(argv):
    from .crossbuild import compare_builds, compare_lines
    from .drift import opened, profiles

    parser = argparse.ArgumentParser(prog="xray compare",
                                     description="compare two builds of the same release (files paired by name)")
    parser.add_argument("left")
    parser.add_argument("right")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-strong", action="store_true", help="exit 1 when a strong difference is found")
    options = _parse(parser, argv)
    with opened(options.left) as (left_label, _, left_files, left_meta), \
            opened(options.right) as (right_label, _, right_files, right_meta):
        report = compare_builds(profiles(left_files), profiles(right_files))

    def label(source, meta):
        return f"{meta['pkgname']} {meta.get('pkgver', '')} ({Path(source).name})" if meta.get("pkgname") else source

    if options.json:
        print(json.dumps({"schema_version": 1, "left": {"source": left_label, **left_meta},
                          "right": {"source": right_label, **right_meta}, **report}, indent=2))
    else:
        print("\n".join(compare_lines(label(left_label, left_meta), label(right_label, right_meta), report)))
    return 1 if options.fail_on_strong and report["strong"] else 0


FEED_USAGE = """usage: xray feed update [--repos core,extra] [--watch NAME...] [--limit N] [--max-mib N] [--quiet]
       xray feed report [--html] [--strong] [--limit N]
       xray feed timer [--install]"""


@_guard
def run_feed(argv):
    import shutil as _shutil
    import sys as _sys

    from . import archfeed, caplog

    if not argv or argv[0] not in ("update", "report", "timer"):
        raise CLIError(FEED_USAGE)
    command = argv[0]
    parser = argparse.ArgumentParser(prog=f"xray feed {command}")
    if command == "update":
        parser.add_argument("--repos", default="core,extra")
        parser.add_argument("--watch", nargs="+", metavar="NAME", help="only these packages (default: all)")
        parser.add_argument("--limit", type=int, metavar="N", help="process at most N updates per repository")
        parser.add_argument("--max-mib", type=int, default=80)
        parser.add_argument("--mirror", help="a Server URL with $repo and $arch (default: /etc/pacman.d/mirrorlist)")
        parser.add_argument("--quiet", action="store_true")
    if command == "report":
        parser.add_argument("--html", action="store_true")
        parser.add_argument("--strong", action="store_true", help="only updates with strong gains")
        parser.add_argument("--limit", type=int, default=50)
    if command == "timer":
        parser.add_argument("--install", action="store_true", help="write the units to ~/.config/systemd/user")
    parser.add_argument("--log", metavar="FILE")
    parser.add_argument("--feed", metavar="FILE")
    parser.add_argument("--state", metavar="FILE")
    options = _parse(parser, argv[1:])
    paths = {key: Path(value) for key, value in (("log", options.log), ("feed", options.feed),
                                                  ("state", options.state)) if value}
    resolved = {**archfeed.default_paths(), **paths}

    if command == "update":
        def progress(repo, number, total, name):
            if not options.quiet and _sys.stderr.isatty():
                print(f"\r{repo} {number}/{total} {name[:40]:<40}", end="", file=_sys.stderr, flush=True)

        first_run = not resolved["state"].exists()
        try:
            entries = archfeed.update([repo.strip() for repo in options.repos.split(",") if repo.strip()],
                                      paths=paths, watch=set(options.watch) if options.watch else None,
                                      max_mib=options.max_mib, limit=options.limit, base_url=options.mirror,
                                      progress=progress)
        except (archfeed.FeedError, OSError) as error:
            raise CLIError(f"feed: {error}") from None
        if not options.quiet and _sys.stderr.isatty():
            print("\r" + " " * 60 + "\r", end="", file=_sys.stderr)
        if first_run:
            print("Started the feed from the current repository versions; later runs record every update.")
            return 0
        strong_count = sum(1 for entry in entries if entry.get("strong"))
        if not options.quiet or strong_count:
            print(f"{len(entries)} updates recorded; {sum(1 for e in entries if e.get('gains'))} gained capabilities, "
                  f"{strong_count} strongly")
            for entry in entries:
                if entry.get("strong"):
                    print(f"  STRONG {entry['package']} {entry['from']} -> {entry['to']}: "
                          + "; ".join(gain["detail"][:80] for gain in entry["strong"][:3]))
        return 0

    if command == "report":
        entries = archfeed.read_feed(resolved["feed"])
        if options.html:
            _, head, _ = caplog.verify(caplog.read_log(resolved["log"]))
            print(archfeed.report_html(entries, head))
        else:
            print("\n".join(archfeed.report_lines(entries, options.limit, options.strong)))
        return 0

    xray_path = _shutil.which("xray") or "xray"
    units = {"xray-feed.service": archfeed.service(xray_path), "xray-feed.timer": archfeed.TIMER}
    if not options.install:
        for name, text in units.items():
            print(f"# ~/.config/systemd/user/{name}\n{text}")
        print("# then: systemctl --user daemon-reload && systemctl --user enable --now xray-feed.timer")
        return 0
    folder = Path.home() / ".config" / "systemd" / "user"
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in units.items():
        (folder / name).write_text(text)
    print(f"wrote {', '.join(units)} to {folder}")
    print("enable with: systemctl --user daemon-reload && systemctl --user enable --now xray-feed.timer")
    return 0


HOOK_USAGE = """usage: xray hook pacman [--block] [--config FILE] [--contracts DIR]   (package names on stdin)
       xray hook install"""


@_guard
def run_hook(argv):
    import shutil as _shutil
    import sys as _sys

    from . import pachook

    if not argv or argv[0] not in ("pacman", "install"):
        raise CLIError(HOOK_USAGE)
    if argv[0] == "install":
        # pacman runs hooks as root: the program it runs must not be writable by an ordinary user.
        found = _shutil.which("xray")
        root_owned = bool(found) and all(
            (info := Path(part).stat()).st_uid == 0 and not info.st_mode & 0o022
            for part in [Path(found).resolve(), *Path(found).resolve().parents])
        xray = str(Path(found).resolve()) if root_owned else "/opt/xray/bin/xray"
        hook = pachook.HOOK.format(xray=xray)
        print("# Install with (needs root):")
        if not root_owned:
            source = Path(__file__).resolve().parent.parent
            print("# A root-owned copy of XRAY for the hook (your own install is user-writable, and pacman runs hooks")
            print("# as root). Once the xray-trust package is installed, use /usr/bin/xray instead.")
            print("sudo python -m venv /opt/xray")
            print(f"sudo /opt/xray/bin/pip install --no-cache-dir '{source}'")
        print("sudo install -d /etc/pacman.d/hooks /etc/xray/contracts")
        print("sudo tee /etc/pacman.d/hooks/90-xray.hook <<'EOF'")
        print(hook.rstrip())
        print("EOF")
        print("sudo tee /etc/xray/hook.conf <<'EOF'")
        print(pachook.CONFIG.rstrip())
        print("EOF")
        print("# Contracts copied into /etc/xray/contracts are re-checked against every upgrade.")
        return 0
    parser = argparse.ArgumentParser(prog="xray hook pacman")
    parser.add_argument("--block", action="store_true", help="exit 1 on strong gains or broken contracts")
    parser.add_argument("--config", default="/etc/xray/hook.conf")
    parser.add_argument("--contracts", default="/etc/xray/contracts")
    parser.add_argument("packages", nargs="*", help="package names (default: read from stdin)")
    options = _parse(parser, argv[1:])
    names = options.packages or [line.strip() for line in _sys.stdin if line.strip()]
    config = pachook.read_config(options.config)
    if options.block:
        config["mode"] = "block"
    lines, block = pachook.check_targets(names, config=config, contracts_dir=options.contracts)
    if lines:
        print("\n".join(lines))
    return 1 if block else 0


@_guard
def run_explain(argv):
    from .explain import explain, explain_lines

    parser = argparse.ArgumentParser(prog="xray explain",
                                     description="which functions call these imported symbols, and on which source line")
    parser.add_argument("file", help="an ELF binary or library")
    parser.add_argument("symbols", nargs="+", help="imported functions, e.g. system connect dlopen")
    parser.add_argument("--json", action="store_true")
    options = _parse(parser, argv)
    if not Path(options.file).is_file():
        raise CLIError(f"not a file: {options.file}")
    sites, how = explain(options.file, options.symbols)
    if options.json:
        print(json.dumps({"schema_version": 1, "file": options.file, "how": how,
                          "sites": [site.__dict__ for site in sites]}, indent=2))
    else:
        print("\n".join(explain_lines(options.file, options.symbols, sites, how)))
    return 0 if sites else 1
