"""Build a minimal root filesystem from evidence: only the files the given commands need.

For each command the evidence graph (and, for a contract, its [exec],
[load] and [read] entries) names the files it runs and loads: the
program, its interpreter, the scripts and commands it runs, every shared
library and the dynamic loader. Those files are copied to the same paths
under the new root, and every symlink they are reached through on this
machine (/bin -> usr/bin, /lib64/ld-linux..., awk -> gawk) is recreated.

The result is checked by running workloads inside it with bubblewrap
(no network, private /tmp), and can be written as a tar archive that
``podman import`` or ``docker import`` accepts.
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

ALWAYS = ("/etc/ld.so.cache",)
DIRECTORY_LIMIT = 64 << 20  # bytes copied from one [read] directory  # optional: the loader falls back to the default directories without it


def _symlink_chain(path):
    """Every symlink met while resolving path on this machine: [(link path, link target)]."""

    links, seen = [], set()
    current = Path("/")
    parts = list(Path(os.path.abspath(path)).parts[1:])
    while parts and len(seen) < 64:
        part = parts.pop(0)
        candidate = current / part
        if candidate.is_symlink():
            target = os.readlink(candidate)
            if str(candidate) in seen:
                break
            seen.add(str(candidate))
            links.append((str(candidate), target))
            resolved = Path(target) if os.path.isabs(target) else current / target
            parts = list(resolved.parts[1:] if resolved.is_absolute() else resolved.parts) + parts
            current = Path("/")
            continue
        current = candidate
    return links


def _reached_through(path, ldcache):
    """Paths other files use to reach this one: its shebang interpreter, PT_INTERP, dir/SONAME links."""

    from .elfscan import scan_elf
    from .libresolve import resolve_library

    out = []
    try:
        with open(path, "rb") as handle:
            first = handle.readline(256)
    except OSError:
        return out
    if first.startswith(b"#!"):
        words = first[2:].decode("utf-8", "replace").split()
        if words and words[0].startswith("/"):
            out.append(words[0])
        return out
    scan = scan_elf(path)
    if scan.interpreter:
        out.append(scan.interpreter)
    for soname in scan.needed:
        found = resolve_library(soname, Path(path).parent, scan.rpath, scan.runpath, (), scan.elf_class,
                                scan.nodeflib, ldcache)
        if found.path is not None:
            candidate = Path(found.directory or found.path.parent) / soname
            if candidate.exists():
                out.append(str(candidate))
    return out


def needed_files(commands=(), contracts=(), depth=8, limit=2000):
    """(files to copy, names to link): resolved files, plus every path through which they are reached."""

    from .contract import expand_home, load_contract
    from .evidence import build_evidence_graph
    from .locate import locate

    files, entry_paths = set(), set()
    shared = {}
    for command in commands:
        path = locate(command) if "/" not in command else Path(command)
        if path is None:
            raise FileNotFoundError(command)
        entry_paths.add(str(path))
        on_path = shutil.which(command) if "/" not in command else None
        if on_path:
            entry_paths.add(on_path)  # the name as found on PATH, often a link (/usr/bin/ls -> .../coreutils/ls)
        graph = build_evidence_graph(str(path), max_depth=depth, max_files=limit, packages=False, shared=shared)
        for node in graph.nodes.values():
            if node.id.startswith("/") and Path(node.id).is_file():
                files.add(node.id)
            if node.kind == "command" and node.attrs.get("resolved") is not False:
                found = shutil.which(node.label) or locate(node.label)
                if found:
                    entry_paths.add(str(found))
        for link in graph.links.values():
            if link.kind == "resolves_to" and link.source.startswith("soname:"):
                # the loader opens dir/SONAME (often a symlink to the versioned file)
                by_name = Path(link.target).parent / link.source.split(":", 1)[1]
                if by_name.exists():
                    entry_paths.add(str(by_name))
            for evidence in link.evidence:
                if evidence.method in ("shebang", "elf-interp"):
                    words = evidence.detail.replace("#!", " ").replace("PT_INTERP", " ").split()
                    entry_paths.update(word for word in words if word.startswith("/"))
    for contract_path in contracts:
        contract = load_contract(contract_path)
        entry_paths.add(contract.program)
        for section in ("exec", "load", "read"):
            for value in contract.values(section):
                path = expand_home(value)
                if "*" in path:
                    continue
                if Path(path).is_file():
                    files.add(os.path.realpath(path))
                    entry_paths.add(path)
                elif section == "read" and Path(path).is_dir():
                    total = 0
                    for found in sorted(Path(path).rglob("*")):  # a read directory comes with its files
                        if found.is_file() and not found.is_symlink():
                            total += found.stat().st_size
                            if total > DIRECTORY_LIMIT:
                                break
                            files.add(str(found))
        for value in contract.values("exec"):
            files.add(os.path.realpath(expand_home(value)))
        from .libresolve import ldconfig_entries

        ldcache = ldconfig_entries()
        for section in ("exec", "load"):
            for value in contract.values(section):
                entry_paths.update(_reached_through(expand_home(value), ldcache))
    files |= {os.path.realpath(path) for path in entry_paths if Path(path).is_file()}
    files |= {path for path in ALWAYS if Path(path).is_file()}
    return sorted(files), sorted(entry_paths)


def build(root, files, entry_paths):
    """Copy files and recreate symlinks under root. Returns (files copied, links made, bytes)."""

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    size = 0
    for path in files:
        target = root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copy2(path, target, follow_symlinks=True)
            size += target.stat().st_size
    links = 0
    for path in entry_paths:
        for link, link_target in _symlink_chain(path):
            target = root / link.lstrip("/")
            if target.is_symlink() or target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(link_target, target)
            links += 1
    for folder in ("tmp", "proc", "dev"):
        (root / folder).mkdir(exist_ok=True)
    os.chmod(root / "tmp", stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO | stat.S_ISVTX)
    return len(files), links, size


def check(root, workload, timeout=30):
    """Run one workload (a command line) inside the root with bubblewrap. Returns CompletedProcess."""

    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise FileNotFoundError("bwrap")
    command = [bwrap, "--bind", str(root), "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
               "--unshare-all", "--die-with-parent", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
               "--setenv", "LANG", "C.UTF-8", "--", *shlex.split(workload)]
    return subprocess.run(command, capture_output=True, timeout=timeout, check=False)


def write_tar(root, output):
    with tarfile.open(output, "w") as archive:
        for path in sorted(Path(root).rglob("*")):
            archive.add(path, arcname=str(path.relative_to(root)), recursive=False)
    return output
