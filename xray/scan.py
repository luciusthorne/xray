"""``xray scan``: read every command on this machine into the evidence store.
``xray reach``: which programs reach a file, library, command or package, with proof.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

from .errors import CLIError
from .evidence import BASES, EVIDENCE_SCHEMA_VERSION, build_evidence_graph, weakest
from .evidencestore import EvidenceStore, path_dirs
from .provenance import packages_of


def _parse(prog, rest, build):
    parser = argparse.ArgumentParser(prog=prog)
    build(parser)
    try:
        return parser.parse_args(rest)
    except SystemExit as stop:
        if stop.code in (0, None):
            raise _Done() from None
        raise CLIError(f"usage: {parser.format_usage().strip()}") from None


class _Done(Exception):
    pass


def _common(parser):
    parser.add_argument("--depth", type=int, default=4, metavar="N", help="follow N steps (default 4)")
    parser.add_argument("--limit", type=int, default=300, metavar="N", help="files per program (default 300)")
    parser.add_argument("--store", metavar="FILE", help="evidence store (default ~/.cache/xray)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")


def commands_in(directories):
    """{command name: file} for executables in directories; the first directory wins."""

    found = {}
    for directory in directories:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in entries:
            if entry.name in found:
                continue
            try:
                if entry.is_file() and os.access(entry.path, os.X_OK):
                    found[entry.name] = entry.path
            except OSError:
                continue
    return found


def run_scan(rest):
    try:
        options = _parse("xray scan", rest, _scan_options)
    except _Done:
        return 0
    directories = options.directories or path_dirs()
    commands = commands_in(directories)
    if options.only:
        commands = {name: path for name, path in commands.items() if name in set(options.only)}
    if not commands:
        raise CLIError("No executable files found to scan")

    started = time.monotonic()
    shared = {}
    graphs = {}
    errors = []
    with EvidenceStore(options.store) as store:
        for number, (name, path) in enumerate(sorted(commands.items()), 1):
            if not options.quiet and sys.stderr.isatty() and number % 25 == 0:
                print(f"\rscanning {number}/{len(commands)}  {name[:40]:<40}", end="", file=sys.stderr, flush=True)
            try:
                graphs[name] = build_evidence_graph(
                    path, max_depth=options.depth, max_files=options.limit,
                    packages=False, store=store, shared=shared,
                )
            except (OSError, FileNotFoundError, RecursionError, ValueError) as error:
                errors.append({"command": name, "path": path, "error": str(error)})
        if not options.quiet and sys.stderr.isatty():
            print("\r" + " " * 70 + "\r", end="", file=sys.stderr)

        files = sorted({node.id for graph in graphs.values() for node in graph.nodes.values() if node.id.startswith("/")})
        owners = {}
        if not options.no_packages:
            for start in range(0, len(files), 2000):
                owners.update(packages_of(files[start:start + 2000]))
            store.set_owners(owners)
        for name, graph in graphs.items():
            _add_packages(graph, owners)
            store.index_program(name, graph, _summary(graph))
        if not options.only:
            store.forget_programs(graphs)
        store.set_meta("last_scan", {"time": time.time(), "epoch": store.epoch, "directories": directories})
        elapsed = time.monotonic() - started
        report = _scan_report(graphs, files, owners, errors, store, elapsed, directories)

    if options.json:
        print(json.dumps(report, indent=2))
    else:
        print("\n".join(_scan_lines(report)))
    return 0


def _scan_options(parser):
    parser.add_argument("directories", nargs="*", help="directories to scan (default: every PATH directory)")
    parser.add_argument("--only", nargs="+", metavar="CMD", help="scan only these command names")
    parser.add_argument("--no-packages", action="store_true", help="skip package ownership lookups")
    parser.add_argument("--quiet", action="store_true", help="no progress line")
    _common(parser)


def _add_packages(graph, owners):
    from .evidence import Evidence

    for node in list(graph.nodes.values()):
        owned = owners.get(node.id)
        if owned is None:
            continue
        manager, owner = owned
        package = graph.add_node(f"package:{owner.split()[0]}", "package", owner, manager=manager)
        query = {"pacman": "pacman -Qo", "rpm": "rpm -qf", "dpkg": "dpkg-query -S"}.get(manager, manager)
        graph.add_link(node.id, package.id, "owned_by", Evidence("declared", manager, f"{query}: {owner}"))


def _summary(graph):
    return {
        "nodes": len(graph.nodes),
        "links": len(graph.links),
        "bases": graph.basis_counts(),
        "risks": graph.risks,
        "blind_spots": len(graph.blind_spots),
        "kind": graph.nodes[graph.root].kind,
    }


def _scan_report(graphs, files, owners, errors, store, elapsed, directories):
    bases = Counter()
    kinds = Counter()
    shared = Counter()
    risks = []
    dynamic = []
    for name, graph in graphs.items():
        bases.update(graph.basis_counts())
        kinds[graph.nodes[graph.root].kind] += 1
        for node in graph.nodes.values():
            if node.id != graph.root and node.kind == "library":
                shared[node.label] += 1
        for entry in graph.risks:
            item = {"command": name, **entry}
            if item not in risks:
                risks.append(item)
        runtime = [entry for entry in graph.blind_spots if "built at runtime" in entry["message"] or "computed at run time" in entry["message"]]
        if runtime and graph.root in {entry["file"] for entry in runtime}:
            dynamic.append(name)
    unique_risks = {}
    for item in risks:
        unique_risks.setdefault((item["file"], item["message"]), []).append(item["command"])
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "programs": len(graphs),
        "kinds": dict(kinds.most_common()),
        "files": len(files),
        "owned_files": len(owners),
        "links": {basis: bases[basis] for basis in BASES},
        "most_reached": shared.most_common(10),
        "risks": [
            {"file": file, "message": message, "reached_by": sorted(set(commands))}
            for (file, message), commands in sorted(unique_risks.items())
        ],
        "runtime_commands": sorted(dynamic),
        "errors": errors,
        "cache": {"hits": store.hits, "misses": store.misses, "store": str(store.path)},
        "seconds": round(elapsed, 1),
        "directories": directories,
    }


def _scan_lines(report):
    kinds = ", ".join(f"{count} {kind}" for kind, count in report["kinds"].items())
    lines = [
        f"Scanned {report['programs']} programs in {report['seconds']}s ({kinds})",
        f"Reached {report['files']} distinct files; {report['owned_files']} owned by packages",
        "Proof per link: " + " · ".join(f"{report['links'][basis]} {basis}" for basis in BASES),
        f"Files read: {report['cache']['misses']} new or changed, {report['cache']['hits']} from the store",
        "",
    ]
    if report["most_reached"]:
        lines.append("Most reached libraries")
        for label, count in report["most_reached"]:
            lines.append(f"  {count:>5}  {label}")
        lines.append("")
    lines.append(f"Worth a look ({len(report['risks'])})")
    for item in report["risks"][:25]:
        users = item["reached_by"]
        who = ", ".join(users[:3]) + (f" and {len(users) - 3} more" if len(users) > 3 else "")
        lines.append(f"  {item['file']}: {item['message']}")
        lines.append(f"      reached by {who}")
    if len(report["risks"]) > 25:
        lines.append(f"  … {len(report['risks']) - 25} more (--json)")
    if not report["risks"]:
        lines.append("  nothing flagged (that is not proof of safety)")
    lines.append("")
    if report["runtime_commands"]:
        lines.append(f"{len(report['runtime_commands'])} programs build commands at run time (see `xray inspect <name>`)")
    if report["errors"]:
        lines.append(f"{len(report['errors'])} programs could not be read (--json lists them)")
    lines.append(f"Store: {report['cache']['store']}")
    lines.append("")
    lines.append("Next")
    lines.append("  xray reach <file|library|command|package>   which programs reach it, with proof")
    return lines


# -- reach ----------------------------------------------------------------------

def _reach_options(parser):
    parser.add_argument("target", help="file path, file or command name, soname (libssl or libssl.so.3), or package")
    parser.add_argument("--chains", type=int, default=5, metavar="N", help="print the proof chain for N programs (default 5)")
    _common(parser)


def run_reach(rest):
    try:
        options = _parse("xray reach", rest, _reach_options)
    except _Done:
        return 0
    store_path = Path(options.store) if options.store else None
    with EvidenceStore(store_path) as store:
        last = store.meta("last_scan")
        if last is None:
            raise CLIError("No scan in the evidence store yet: run `xray scan` first")
        programs = store.programs()
        candidates = store.reaching(options.target)
        owners = store.owners()
        found = []
        for command in candidates:
            program = programs.get(command)
            if program is None or not Path(program["root"]).exists():
                continue
            graph = build_evidence_graph(
                program["root"], max_depth=options.depth, max_files=options.limit,
                packages=bool(owners), store=store, owners=owners,
            )
            matches = graph.find(options.target)
            paths = graph.paths(matches, max_paths=1) if matches else []
            if paths:
                found.append((command, graph, paths[0]))
        stale = last["epoch"] != store.epoch

    found.sort(key=lambda item: (BASES.index(weakest(link.basis for link in item[2])), len(item[2]), item[0]))
    if options.json:
        print(json.dumps(_reach_data(options.target, found, len(programs), stale), indent=2))
    else:
        print("\n".join(_reach_lines(options.target, found, len(programs), stale, options.chains)))
    return 0 if found else 1


def reach_programs(target, store_path=None, depth=4, limit=300):
    """[(command, weakest basis, short chain)], scanned program count, stale flag."""

    with EvidenceStore(Path(store_path) if store_path else None) as store:
        last = store.meta("last_scan")
        if last is None:
            raise CLIError("No scan in the evidence store yet: run `xray scan` first")
        programs = store.programs()
        owners = store.owners()
        found = []
        for command in store.reaching(target):
            program = programs.get(command)
            if program is None or not Path(program["root"]).exists():
                continue
            graph = build_evidence_graph(program["root"], max_depth=depth, max_files=limit,
                                         packages=bool(owners), store=store, owners=owners)
            matches = graph.find(target)
            paths = graph.paths(matches, max_paths=1) if matches else []
            if paths:
                found.append((command, weakest(link.basis for link in paths[0]), _steps(graph, paths[0])))
        stale = last["epoch"] != store.epoch
    found.sort(key=lambda item: (BASES.index(item[1]), item[0]))
    return found, len(programs), stale


def _steps(graph, path):
    return " → ".join(
        Path(_label(graph, link.target)).name or _label(graph, link.target)
        for position, link in enumerate(path)
        if not (position + 1 < len(path) and path[position + 1].kind == "resolves_to")
    )


def _label(graph, node_id):
    node = graph.nodes.get(node_id)
    if node is None:
        return node_id
    if node.kind in ("command", "soname", "package"):
        return node.label
    return node.id


def _reach_data(target, found, total, stale):
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "query": target,
        "scanned_programs": total,
        "stale": stale,
        "programs": [
            {
                "command": command,
                "root": graph.root,
                "basis": weakest(link.basis for link in path),
                "links": [link.to_dict() for link in path],
            }
            for command, graph, path in found
        ],
    }


def _reach_lines(target, found, total, stale, chains):
    lines = []
    if stale:
        lines.append("Note: programs were installed or removed since the last scan; run `xray scan` to refresh.")
    if not found:
        lines.append(f"None of the {total} scanned programs reach anything matching '{target}'.")
        lines.append("Not found is not proof of absence: programs reach things at run time that no file names.")
        return lines
    lines.append(f"{len(found)} of {total} scanned programs reach {target}")
    lines.append("")
    by_basis = Counter(weakest(link.basis for link in path) for _, _, path in found)
    lines.append("By weakest link: " + " · ".join(f"{by_basis[basis]} {basis}" for basis in BASES))
    lines.append("")
    width = min(24, max(len(command) for command, _, _ in found))
    for command, graph, path in found:
        strength = weakest(link.basis for link in path)
        steps = " → ".join(
            Path(_label(graph, link.target)).name or _label(graph, link.target)
            for position, link in enumerate(path)
            if not (position + 1 < len(path) and path[position + 1].kind == "resolves_to")
        )
        lines.append(f"  {command:<{width}}  [{strength}]  {steps}")
    for command, graph, path in found[:chains]:
        lines.append("")
        lines.append(f"Proof: {command}")
        lines.append(f"  {graph.root}")
        for link in path:
            evidence = min(link.evidence, key=lambda item: BASES.index(item.basis))
            where = evidence.where()
            lines.append(f"    └─ {link.kind}  [{link.basis}]  {evidence.detail}" + (f"  ({where})" if where else ""))
            lines.append(f"  {_label(graph, link.target)}")
    return lines
