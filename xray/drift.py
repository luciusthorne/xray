"""Capability drift between two versions of software, and what an upgrade or removal would touch.

A side of a comparison is a file, a directory, a package archive
(pacman .pkg.tar.*, .rpm or any tar that bsdtar reads) or an installed
package (``installed:NAME``). Each executable, library and script is
profiled (xray.profile) and the two sides are compared path by path.
A *gain* is a capability the new version has and the old did not: a
new class of imported calls (network, starting programs, loading code,
changing identity, ptrace, kernel), a new library or search path, more
IFUNC resolvers or constructors (code that runs before main), a new
setuid bit, a new command a script runs.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .errors import CLIError
from .profile import interesting, loader_hook, profile

ARCHIVE_SUFFIXES = (".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar", ".rpm", ".deb", ".tar.gz", ".tgz",
                    ".tar.xz", ".tar.zst", ".tar")


LOADER_HOOK = ("links the dynamic loader and has IFUNC resolvers: code that runs inside the loader before main, "
               "the hook of the 2024 xz backdoor (outside glibc this combination is otherwise unseen)")


def is_archive(path):
    return str(path).endswith(ARCHIVE_SUFFIXES)


def read_deb_control(text):
    """pkgname/pkgver/arch from a Debian control file."""

    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and not line.startswith(" "):
            fields[key.strip()] = value.strip()
    info = {}
    for key, name in (("Package", "pkgname"), ("Version", "pkgver"), ("Architecture", "arch"), ("Maintainer", "packager")):
        if fields.get(key):
            info[name] = fields[key]
    return info


def _extract_deb(path, folder):
    """Unpack a .deb (an ar archive) into folder; return its control metadata."""

    outer = Path(folder) / ".deb"
    outer.mkdir()
    done = subprocess.run(["bsdtar", "-xf", str(path), "-C", str(outer)], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise CLIError(f"cannot extract {path}: {done.stderr.strip()[:200]}")
    data = sorted(outer.glob("data.tar*"))
    control = sorted(outer.glob("control.tar*"))
    if not data:
        raise CLIError(f"{path} has no data.tar member")
    subprocess.run(["bsdtar", "-xf", str(data[0]), "-C", str(folder)], check=True, capture_output=True)
    meta = {}
    if control:
        target = outer / "control"
        target.mkdir()
        subprocess.run(["bsdtar", "-xf", str(control[0]), "-C", str(target)], check=True, capture_output=True)
        control_file = target / "control"
        if control_file.is_file():
            meta = read_deb_control(control_file.read_text(encoding="utf-8", errors="replace"))
    shutil.rmtree(outer)
    return meta


def read_pkginfo(root):
    info = {}
    path = Path(root) / ".PKGINFO"
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition(" = ")
            if key in ("pkgname", "pkgver", "arch", "packager", "builddate") and value:
                info.setdefault(key, value)
    return info


@contextmanager
def opened(source):
    """Yield (label, root, files, meta): files maps relative paths to real files."""

    source = str(source)
    if source.startswith("installed:"):
        name = source.split(":", 1)[1]
        files = installed_files(name)
        if not files:
            raise CLIError(f"no installed package named {name} (or no pacman/rpm database)")
        yield source, "/", {path.lstrip("/"): path for path in files}, {"pkgname": name}
        return
    path = Path(source).expanduser()
    if not path.exists():
        raise CLIError(f"not found: {source}")
    if path.is_file() and is_archive(path):
        if shutil.which("bsdtar") is None:
            raise CLIError("bsdtar (libarchive) is needed to read package archives")
        with tempfile.TemporaryDirectory(prefix="xray-drift-") as folder:
            if str(path).endswith(".deb"):
                meta = _extract_deb(path, folder)
                yield str(path), folder, _walk(folder), meta
                return
            done = subprocess.run(["bsdtar", "-xf", str(path), "-C", folder], capture_output=True, text=True,
                                  check=False)
            if done.returncode != 0:
                raise CLIError(f"cannot extract {source}: {done.stderr.strip()[:200]}")
            yield str(path), folder, _walk(folder), read_pkginfo(folder)
        return
    if path.is_dir():
        yield str(path), str(path), _walk(path), read_pkginfo(path)
        return
    yield str(path), str(path.parent), {path.name: str(path)}, {}


def _walk(root):
    files = {}
    for directory, dirs, names in os.walk(root):
        dirs.sort()
        for name in sorted(names):
            if name.startswith(".") and directory == str(root):
                continue  # .PKGINFO, .MTREE, .BUILDINFO
            full = Path(directory) / name
            if interesting(full):
                files[str(full.relative_to(root))] = str(full)
    return files


def installed_files(name, everything=False):
    """Files of an installed package: the ones worth profiling, or with everything all of them."""

    for command in (["pacman", "-Qlq", name], ["rpm", "-ql", name]):
        if shutil.which(command[0]) is None:
            continue
        done = subprocess.run(command, capture_output=True, text=True, check=False)
        if done.returncode == 0:
            lines = [line for line in done.stdout.splitlines() if line and not line.endswith("/")]
            return lines if everything else [line for line in lines if interesting(Path(line))]
    return []


def profiles(files):
    out = {}
    for relative, real in files.items():
        try:
            out[relative] = profile(real)
        except OSError:
            continue
    return out


def stem(name):
    """A name without version numbers and build hashes: libHSaeson-2.2.4.0-9J6q…-ghc9.6.7.so -> libHSaeson-ghc9-so."""

    tokens = re.split(r"[-._]", Path(name).name)
    def hashlike(token):
        digits = any(ch.isdigit() for ch in token)
        mixed = any(ch.islower() for ch in token) and sum(ch.isupper() for ch in token) >= 3
        return (len(token) >= 12 and digits and any(ch.isalpha() for ch in token)) or (len(token) >= 16 and mixed)

    kept = [token for token in tokens if token and not token.isdigit() and not hashlike(token)]
    return "-".join(kept)


def _version_free(directory):
    return re.sub(r"\d+(?:\.\d+)*", "#", directory)


def _paired(added, removed):
    """Pairs (removed, added) whose stems match one to one; the rest stay unpaired."""

    by_stem = {}
    for item in removed:
        by_stem.setdefault(stem(item), [[], []])[0].append(item)
    for item in added:
        by_stem.setdefault(stem(item), [[], []])[1].append(item)
    pairs = [(olds[0], news[0]) for olds, news in by_stem.values() if len(olds) == 1 and len(news) == 1]
    return pairs


def _new_search_entries(old, new):
    """Search path entries in new that are not old ones with another version number or a trailing slash."""

    def normal(entry):
        return re.sub(r"\d+(?:\.\d+)*", "#", entry.rstrip("/") or "/")

    before = {normal(entry) for entry in (old or "").split(":") if entry}
    return [entry for entry in (new or "").split(":") if entry and normal(entry) not in before]


def _set_change(old, new, key):
    before, after = set(old.get(key) or ()), set(new.get(key) or ())
    return sorted(after - before), sorted(before - after)


def compare(old, new):
    """Changes from profile old to profile new: a list of {kind, field, detail} items."""

    changes = []

    def add(kind, field, detail):
        changes.append({"kind": kind, "field": field, "detail": detail})

    if old["kind"] != new["kind"]:
        add("change", "kind", f"{old['kind']} -> {new['kind']}")
    old_classes, new_classes = old.get("classes") or {}, new.get("classes") or {}
    for cls in sorted(set(old_classes) | set(new_classes)):
        before, after = set(old_classes.get(cls, ())), set(new_classes.get(cls, ()))
        if after and not before:
            add("gain", f"class:{cls}", f"now uses {cls}: {', '.join(sorted(after))}")
        elif after - before:
            add("gain", f"class:{cls}", f"more {cls} calls: {', '.join(sorted(after - before))}")
        if before and not after:
            add("loss", f"class:{cls}", f"no longer uses {cls}")
    for key, label in (("needed", "library"), ("commands", "command"), ("sources", "sourced file"),
                       ("imports", "module")):
        if key not in old and key not in new:
            continue
        if not isinstance(old.get(key, []), list) or not isinstance(new.get(key, []), list):
            continue
        added, removed = _set_change(old, new, key)
        if key == "needed":
            pairs = _paired(added, removed)
            for before, after in pairs:
                add("change", key, f"library version: {before} -> {after}")
            added = [item for item in added if item not in {after for _, after in pairs}]
            removed = [item for item in removed if item not in {before for before, _ in pairs}]
        for item in added:
            # A new module import matters through the capability classes above.
            add("change" if key == "imports" else "gain", key, f"new {label}: {item}")
        for item in removed:
            add("loss", key, f"dropped {label}: {item}")
    for key in ("rpath", "runpath", "interpreter", "soname"):
        if old.get(key) != new.get(key):
            kind = "gain" if key in ("rpath", "runpath") and _new_search_entries(old.get(key), new.get(key)) else "change"
            add(kind, key, f"{key}: {old.get(key) or '-'} -> {new.get(key) or '-'}")
    for key, label in (("ifuncs", "IFUNC resolvers"), ("constructors", "constructors run before main")):
        before, after = old.get(key) or 0, new.get(key) or 0
        if after > before:
            add("gain", key, f"{label}: {before} -> {after}")
    for key in ("setuid", "setgid"):
        if new.get(key) and not old.get(key):
            add("gain", key, f"now {key}")
        elif old.get(key) and not new.get(key):
            add("loss", key, f"no longer {key}")
    if (new.get("dynamic") or 0) > (old.get("dynamic") or 0):
        add("gain", "dynamic", f"commands built at run time: {old.get('dynamic') or 0} -> {new['dynamic']}")
    if old.get("changes_path") is False and new.get("changes_path"):
        add("gain", "changes_path", "now assigns PATH")
    return changes


def drift(old_profiles, new_profiles):
    """Compare two {path: profile} maps; return the report as plain data."""

    added = sorted(set(new_profiles) - set(old_profiles))
    removed = sorted(set(old_profiles) - set(new_profiles))
    renamed = [
        (before, after) for before, after in _paired(added, removed)
        if str(Path(before).parent) == str(Path(after).parent)
    ]
    added = [path for path in added if path not in {after for _, after in renamed}]
    removed = [path for path in removed if path not in {before for before, _ in renamed}]
    # Files that moved into a versioned directory (usr/lib/perl5/5.42/... -> 5.44/...) pair by directory
    # pattern and name stem.
    moved = [
        (before, after) for before, after in _paired(added, removed)
        if _version_free(str(Path(before).parent)) == _version_free(str(Path(after).parent))
    ]
    renamed += moved
    added = [path for path in added if path not in {after for _, after in moved}]
    removed = [path for path in removed if path not in {before for before, _ in moved}]
    changed, same = [], 0
    pairs = [(path, path) for path in sorted(set(old_profiles) & set(new_profiles))] + renamed
    for before, path in pairs:
        old, new = old_profiles[before], new_profiles[path]
        if old["sha256"] == new["sha256"]:
            same += 1
            continue
        changes = compare(old, new)
        entry = {"path": path, "changes": changes}
        if before != path:
            changes.insert(0, {"kind": "change", "field": "path", "detail": f"renamed from {before}"})
            entry["renamed_from"] = before
        changed.append(entry)
    for item in changed:
        before = item.get("renamed_from") or item["path"]
        if loader_hook(new_profiles[item["path"]], item["path"]) and not loader_hook(old_profiles[before], before):
            item["changes"].insert(0, {"kind": "gain", "field": "loader-hook", "detail": LOADER_HOOK})
    gains = [
        {"path": item["path"], **change} for item in changed for change in item["changes"] if change["kind"] == "gain"
    ]
    for path in added:
        classes = new_profiles[path].get("classes") or {}
        for cls, names in sorted(classes.items()):
            gains.append({"path": path, "kind": "gain", "field": f"class:{cls}",
                          "detail": f"new file uses {cls}: {', '.join(names)}"})
        if new_profiles[path].get("setuid"):
            gains.append({"path": path, "kind": "gain", "field": "setuid", "detail": "new setuid file"})
        if loader_hook(new_profiles[path], path):
            gains.insert(0, {"path": path, "kind": "gain", "field": "loader-hook", "detail": LOADER_HOOK})
    return {
        "added": [{"path": path, "kind": new_profiles[path]["kind"]} for path in added],
        "removed": [{"path": path, "kind": old_profiles[path]["kind"]} for path in removed],
        "changed": changed,
        "unchanged": same,
        "gains": gains,
    }


def drift_lines(old_label, new_label, report, old_meta=None, new_meta=None):
    def name(label, meta):
        if meta and meta.get("pkgname"):
            return f"{meta['pkgname']} {meta.get('pkgver', '')}".strip()
        return label

    lines = [f"Drift from {name(old_label, old_meta)} to {name(new_label, new_meta)}", ""]
    changed_content = [item for item in report["changed"]]
    lines.append(
        f"{len(report['added'])} files added, {len(report['removed'])} removed, "
        f"{len(changed_content)} changed, {report['unchanged']} identical"
    )
    lines.append("")
    if report["gains"]:
        lines.append(f"Capabilities gained ({len(report['gains'])})")
        for item in report["gains"]:
            lines.append(f"  {item['path']}: {item['detail']}")
    else:
        lines.append("No capabilities gained.")
    others = [(item["path"], change) for item in report["changed"] for change in item["changes"]
              if change["kind"] != "gain" and change["detail"].split(":")[0] != "library version"]
    versions = sum(1 for item in report["changed"] for change in item["changes"]
                   if change["detail"].startswith("library version"))
    if others:
        lines.append("")
        lines.append("Other changes")
        for path, change in others[:40]:
            lines.append(f"  {path}: {change['detail']}")
        if len(others) > 40:
            lines.append(f"  … {len(others) - 40} more (--json)")
    if versions:
        lines.append("")
        lines.append(f"{versions} needed libraries changed version or build hash (--json lists them)")
    quiet = [item["path"] for item in report["changed"] if not item["changes"]]
    if quiet:
        lines.append("")
        lines.append(f"{len(quiet)} files changed content without a capability change")
    if report["added"]:
        lines.append("")
        lines.append("Added: " + ", ".join(item["path"] for item in report["added"][:15])
                     + (" …" if len(report["added"]) > 15 else ""))
    if report["removed"]:
        lines.append("Removed: " + ", ".join(item["path"] for item in report["removed"][:15])
                     + (" …" if len(report["removed"]) > 15 else ""))
    lines.append("")
    lines.append("A profile reads imported calls, libraries and commands; code paths that use no new")
    lines.append("import (for example a syscall made directly) are not seen. No change is not proof of safety.")
    return lines
