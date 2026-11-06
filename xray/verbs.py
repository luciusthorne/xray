"""Verb commands built on the evidence graph: inspect, why, scan and reach."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .errors import CLIError
from .evidence import (
    BASES,
    EVIDENCE_SCHEMA_VERSION,
    add_trace,
    build_evidence_graph,
    weakest,
)

VERBS = ("inspect", "why", "scan", "reach", "contract", "drift", "whatif", "log", "taint", "compare", "feed", "hook", "explain", "attest", "policy", "query")


def _parser(verb):
    parser = argparse.ArgumentParser(prog=f"xray {verb}", add_help=True)
    parser.add_argument("command", help="command name on PATH, or a path to a file")
    if verb == "why":
        parser.add_argument(
            "target",
            help="file path, file or command name, soname (libssl or libssl.so.3), or package",
        )
        parser.add_argument("--paths", type=int, default=3, metavar="N", help="show up to N paths (default 3)")
    parser.add_argument("--depth", type=int, default=4, metavar="N", help="follow N steps (default 4)")
    parser.add_argument("--limit", type=int, default=300, metavar="N", help="add at most N files (default 300)")
    parser.add_argument("--no-packages", action="store_true", help="skip package ownership lookups")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    if verb == "inspect":
        parser.add_argument("--all", action="store_true", help="list every direct link")
        parser.add_argument("--tree", action="store_true", help="print the whole graph as a tree, with the basis of each link")
        parser.add_argument("--html", action="store_true", help="print an interactive evidence graph page (save it with >)")
        parser.add_argument("--sbom", choices=("cyclonedx", "spdx"), help="print a bill of materials of what it reaches")
        parser.add_argument(
            "--trace", action="store_true",
            help="also RUN the command under strace and compare what it did with the static graph",
        )
        parser.add_argument("--timeout", type=int, default=10, metavar="S", help="trace timeout in seconds")
        parser.add_argument("args", nargs="*", help="arguments for --trace (put them after --)")
    return parser


def run_verb(argv):
    verb, rest = argv[0], argv[1:]
    if verb == "taint":
        return run_taint(rest)
    if verb in ("drift", "whatif", "log", "compare", "feed", "hook", "explain", "attest", "policy", "query"):
        from .driftverbs import (
            run_attest,
            run_compare,
            run_drift,
            run_explain,
            run_feed,
            run_hook,
            run_log,
            run_policy,
            run_query,
            run_whatif,
        )

        return {"drift": run_drift, "whatif": run_whatif, "log": run_log, "compare": run_compare,
                "feed": run_feed, "hook": run_hook, "explain": run_explain, "attest": run_attest,
                "policy": run_policy, "query": run_query}[verb](rest)
    if verb == "contract":
        from .contractverbs import run_contract

        return run_contract(rest)
    if verb in ("scan", "reach"):
        from .scan import run_reach, run_scan

        return run_scan(rest) if verb == "scan" else run_reach(rest)
    parser = _parser(verb)
    try:
        options = parser.parse_args(rest)
    except SystemExit as stop:
        if stop.code in (0, None):
            return 0
        raise CLIError(f"usage: {parser.format_usage().strip()}") from None
    for name in ("depth", "limit"):
        if getattr(options, name) < 1:
            raise CLIError(f"--{name} must be at least 1")

    try:
        graph = build_evidence_graph(
            options.command,
            max_depth=options.depth,
            max_files=options.limit,
            packages=not options.no_packages,
        )
    except FileNotFoundError:
        raise CLIError(f"Not found on PATH or disk: {options.command}") from None

    if verb == "inspect":
        if options.trace:
            from .trace import run_trace

            add_trace(graph, run_trace(graph.root, options.args, timeout=options.timeout))
        if options.json:
            print(json.dumps(graph.to_dict(), indent=2))
        elif options.html:
            from .evidencehtml import render

            print(render(graph))
        elif options.sbom:
            from .sbom import cyclonedx, spdx

            print(json.dumps(cyclonedx(graph) if options.sbom == "cyclonedx" else spdx(graph), indent=2))
        elif options.tree:
            print("\n".join(tree_lines(graph)))
        else:
            print("\n".join(inspect_lines(graph, show_all=options.all)))
        return 0

    matches = graph.find(options.target)
    paths = graph.paths(matches, max_paths=options.paths) if matches else []
    if options.json:
        print(json.dumps(why_data(graph, options.target, paths), indent=2))
    else:
        print("\n".join(why_lines(graph, options.target, paths, matches, options.depth)))
    return 0 if paths else 1


# -- formatting ---------------------------------------------------------------

def _short(graph, node_id):
    node = graph.nodes.get(node_id)
    if node is None:
        return node_id
    if node.kind in ("command", "soname", "package"):
        return node.label
    return node_id


def _where(evidence):
    where = evidence.where()
    return f"  ({where})" if where else ""


def _package_of(graph, node_id):
    for link in graph.outgoing(node_id):
        if link.kind == "owned_by":
            return graph.nodes[link.target]
    return None


def inspect_lines(graph, show_all=False, limit=25):
    root = graph.nodes[graph.root]
    package = _package_of(graph, graph.root)
    owner = f"  {package.label} ({package.attrs.get('manager')})" if package else ""
    lines = [f"{root.label}  {root.id}  [{root.kind}]{owner}", ""]

    kinds = Counter(node.kind for node in graph.nodes.values() if node.id != graph.root)
    files = sum(count for kind, count in kinds.items() if kind not in ("command", "soname", "package"))
    unresolved = [node for node in graph.nodes.values() if node.attrs.get("resolved") is False]
    lines.append(
        f"Reaches {files} files and {kinds.get('package', 0)} packages through {len(graph.links)} links"
    )
    counts = graph.basis_counts()
    proof = " · ".join(f"{counts[basis]} {basis}" for basis in BASES)
    lines.append(f"Proof per link: {proof}")
    if graph.trace is None:
        lines.append("Nothing was run: links are from metadata and code only (add --trace to observe a run).")
    lines.append("")

    lines.append("Direct links")
    direct = graph.outgoing(graph.root)
    direct = [
        link for link in direct
        if link.kind not in ("owned_by", "executed", "opened")
        and graph.nodes[link.target].attrs.get("resolved") is not False
    ]
    shown = direct if show_all else direct[:limit]
    for link in shown:
        label = _short(graph, link.target)
        then = ""
        if link.kind in ("runs", "needs"):
            onward = [step for step in graph.outgoing(link.target) if step.kind == "resolves_to"]
            if onward:
                then = f" -> {onward[0].target}  [{onward[0].basis}]"
        evidence = link.evidence[0]
        lines.append(f"  {link.kind:<12} {label}{then}")
        lines.append(f"  {'':<12}   {link.basis}: {evidence.detail}{_where(evidence)}")
    if len(direct) > len(shown):
        lines.append(f"  … {len(direct) - len(shown)} more (--all)")
    if not direct:
        lines.append("  none found")
    lines.append("")

    packages = sorted(node.label for node in graph.nodes.values() if node.kind == "package")
    if packages:
        lines.append(f"Packages reached ({len(packages)})")
        lines.extend(_wrap(packages))
        lines.append("")

    if unresolved:
        lines.append(f"Named but not found ({len(unresolved)})")
        lines.extend(_wrap(sorted(node.label for node in unresolved)))
        lines.append("")

    if graph.trace is not None:
        unpredicted = graph.trace["unpredicted"]
        status = "timed out" if graph.trace["timed_out"] else f"exit status {graph.trace['status']}"
        observed = sum(1 for node in graph.nodes.values() if node.attrs.get("observed"))
        lines.append(f"Traced run ({status})")
        lines.append(f"  {observed} files touched; {len(unpredicted)} were not predicted by static analysis")
        for item in unpredicted[:limit]:
            lines.append(f"  {item['kind']:<9} {item['path']}")
        if len(unpredicted) > limit:
            lines.append(f"  … {len(unpredicted) - limit} more (--json)")
        lines.append("")

    if graph.risks:
        lines.append(f"Worth a look ({len(graph.risks)})")
        for entry in graph.risks[:limit]:
            lines.append(f"  {entry['file']}: {entry['message']}")
        lines.append("")

    lines.append("Blind spots (what this graph cannot show)")
    for entry in graph.blind_spots[:limit]:
        where = "" if entry["file"] == "*" else f"{entry['file']}: "
        lines.append(f"  {where}{entry['message']}")
    if len(graph.blind_spots) > limit:
        lines.append(f"  … {len(graph.blind_spots) - limit} more (--json)")
    for note in graph.truncated[:1]:
        lines.append(f"  truncated: {note} (raise --limit or --depth)")
    not_expanded = sum(1 for node in graph.nodes.values() if node.attrs.get("not_expanded"))
    if not_expanded:
        lines.append(f"  {not_expanded} files at the depth limit were not read (raise --depth)")
    lines.append("  Commands run only through variables, eval or other languages are not linked.")
    lines.append("")
    lines.append("Next")
    lines.append(f"  xray why {root.label} <name>      proof chain to a file, command, library or package")
    lines.append(f"  xray inspect {root.label} --json  the whole graph with every piece of evidence")
    return lines


def tree_lines(graph):
    """The graph as a tree from the root: one line per link, with its basis.

    A command or soname and the file it resolves to share one line. A
    file seen before is marked (seen) and not expanded again.
    """

    root = graph.nodes[graph.root]
    lines = [f"{root.id} [{root.kind}]"]
    seen = {graph.root}

    def children(node_id):
        found = [link for link in graph.outgoing(node_id) if link.kind not in ("owned_by",)]
        return sorted(found, key=lambda link: (link.kind, _short(graph, link.target)))

    def walk(node_id, prefix):
        links = children(node_id)
        for index, link in enumerate(links):
            last = index == len(links) - 1
            branch = "└── " if last else "├── "
            evidence = min(link.evidence, key=lambda item: BASES.index(item.basis))
            where = evidence.where()
            line_no = f":{evidence.line}" if evidence.line and where else ""
            target = link.target
            basis = link.basis
            onward = [step for step in graph.outgoing(target) if step.kind == "resolves_to"]
            label = _short(graph, target)
            if onward:
                target = onward[0].target
                basis = weakest([basis, onward[0].basis])
                label += f" -> {target}"
            node = graph.nodes.get(target)
            kind = f" [{node.kind}]" if node is not None and node.kind not in ("command", "soname") else ""
            missing = " (not found)" if node is not None and node.attrs.get("resolved") is False else ""
            tag = f"  {basis}" + (f" line {line_no[1:]}" if line_no else "")
            text = f"{prefix}{branch}{link.kind} {label}{kind}{missing}{tag}"
            if target in seen:
                lines.append(text + " (seen)")
                continue
            seen.add(target)
            lines.append(text)
            walk(target, prefix + ("    " if last else "│   "))

    walk(graph.root, "")
    not_expanded = sum(1 for node in graph.nodes.values() if node.attrs.get("not_expanded"))
    if not_expanded:
        lines.append(f"Truncated: {not_expanded} files at the depth limit were not read (raise --depth)")
    for note in graph.truncated[:1]:
        lines.append(f"Truncated: {note}")
    return lines


def _wrap(words, width=76):
    lines, current = [], "  "
    for word in words:
        piece = word + ", "
        if len(current) + len(piece) > width and current.strip():
            lines.append(current.rstrip(", "))
            current = "  "
        current += piece
    if current.strip():
        lines.append(current.rstrip(", "))
    return lines


def why_lines(graph, query, paths, matches, depth):
    root = graph.nodes[graph.root]
    if not matches:
        return [
            f"{root.label} does not reach anything matching '{query}' within {depth} steps.",
            (
                "Not found is not proof of absence: see the blind spots in "
                f"`xray inspect {root.label}`, or raise --depth."
            ),
        ]
    if not paths:
        return [f"'{query}' is in the graph but no path from {root.label} leads to it."]

    lines = [f"Why does {root.label} reach {query}?", ""]
    for number, path in enumerate(paths, 1):
        strength = weakest(link.basis for link in path)
        lines.append(f"Path {number}: {len(path)} steps, as strong as its weakest link: {strength}")
        lines.append(f"  {_short(graph, path[0].source)}")
        for link in path:
            evidence = min(link.evidence, key=lambda item: BASES.index(item.basis))
            lines.append(f"    └─ {link.kind}  [{link.basis}]  {evidence.detail}{_where(evidence)}")
            lines.append(f"  {_short(graph, link.target)}")
        lines.append("")
    lines.append("Bases: observed (seen in a run) > declared (metadata the system acts on) >")
    lines.append("       inferred (read from code, resolved as this machine would) > guessed.")
    return lines


def why_data(graph, query, paths):
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "root": graph.root,
        "query": query,
        "paths": [
            {
                "basis": weakest(link.basis for link in path),
                "links": [link.to_dict() for link in path],
            }
            for path in paths
        ],
    }


def is_verb(argv):
    """True when argv names a verb (and not an existing file called like one)."""

    return bool(argv) and argv[0] in VERBS and not Path(argv[0]).exists()


def run_taint(argv):
    import sys

    from .taint import analyze, report_lines, scan_scripts

    parser = argparse.ArgumentParser(prog="xray taint")
    parser.add_argument("command", nargs="?", help="command name or path (omit with --scan)")
    parser.add_argument("--scan", nargs="*", metavar="DIR", help="analyse every shell and Python command on PATH (or in DIRs)")
    parser.add_argument("--all", action="store_true", help="also show low-severity findings")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--depth", type=int, default=4)
    try:
        options = parser.parse_args(argv)
    except SystemExit as stop:
        if stop.code in (0, None):
            return 0
        raise CLIError(f"usage: {parser.format_usage().strip()}") from None

    if options.scan is not None:
        def progress(number, total, name):
            if sys.stderr.isatty():
                print(f"\rtaint {number}/{total} {name[:40]:<40}", end="", file=sys.stderr, flush=True)

        results = scan_scripts(options.scan or None, progress=progress)
        if sys.stderr.isatty():
            print("\r" + " " * 60 + "\r", end="", file=sys.stderr)
        rows = [(name, item) for name, report in results for item in report.findings
                if options.all or item["severity"] in ("high", "medium")]
        if options.json:
            print(json.dumps({"schema_version": 1, "programs": len(results),
                              "findings": [{"command": name, **item} for name, item in rows]}, indent=2))
            return 0
        counts = Counter(item["severity"] for _, item in rows)
        affected = len({name for name, _ in rows})
        print(f"Analysed {len(results)} shell and Python commands; {affected} have findings: "
              + ", ".join(f"{counts[level]} {level}" for level in ("high", "medium", "low", "info") if counts[level]))
        print()
        for name, item in rows:
            where = f"{item['file']}:{item['line']}" if item["line"] else item["file"]
            via = f"  via {Path(item['chain'][-1]['file']).name}" if item["chain"] else ""
            print(f"  [{item['severity']}] {name}: {item['detail']}  ({where}; from {', '.join(item['sources'])}){via}")
        print()
        print("Findings are leads inferred from code, not proof: review each one.")
        return 0

    if not options.command:
        raise CLIError("usage: xray taint COMMAND | xray taint --scan [DIR...]")
    try:
        report = analyze(options.command, max_depth=options.depth)
    except FileNotFoundError:
        raise CLIError(f"Not found on PATH or disk: {options.command}") from None
    if options.json:
        print(json.dumps({"schema_version": 1, "root": report.root, "findings": report.findings,
                          "followed": report.followed, "blind_spots": report.blind_spots}, indent=2))
    else:
        print("\n".join(report_lines(report, show_low=options.all)))
    return 1 if any(item["severity"] == "high" for item in report.findings) else 0
