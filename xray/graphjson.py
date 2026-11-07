from collections import deque
from pathlib import Path

from . import __version__, command_analyzers, python_analyzer  # noqa: F401  (register analyzers)
from .analyzers import registry
from .disasm import disasm_result
from .entrypoints import command_kind
from .errors import XRAYError
from .graph import DependencyGraph
from .identify import get_file_metadata
from .model import (
    LANGUAGE_NAMES,
    MODEL_SCHEMA_VERSION,
    Edge,
    FileInfo,
    edge_data,
    symbol_data,
)
from .provenance import package_of

EXPANDABLE = (
    "python", "shell", "elf", "perl", "ruby", "javascript", "lua", "typescript", "c", "lisp"
)


def _symbols(path, kind):
    if kind not in ("python", "shell", "ruby", "javascript", "lua", "typescript", "c", "lisp"):
        return []

    analyzer = registry.analyzer_for(path)

    if analyzer is None:
        return []

    try:
        return analyzer.symbols(path)
    except XRAYError:
        return []


def _children(path, kind):
    """Return (edge kind, target, name, status, target kind) tuples.

    target is a Path when the relationship resolved and None when not.
    """

    found = []

    analyzer = registry.analyzer_for(path)

    if analyzer is None:
        return found

    for edge in analyzer.command_edges(path):
        if edge.status != "resolved" or edge.target is None:
            found.append((edge.kind, None, edge.name, edge.status, None))
            continue

        target = Path(edge.target)
        target_kind = (
            "library" if edge.kind == "links" else command_kind(target)
        )
        found.append((edge.kind, target, edge.name, "resolved", target_kind))

    return found


def command_graph(path):
    """Return the file graph of a command as a DependencyGraph.

    Nodes are absolute paths, edges are the resolved relationships
    graph_data finds, and unresolved ones are left out. The graph
    options (--tree, --deps, --impact, ...) run on it unchanged.
    """

    data = graph_data(path)
    graph = DependencyGraph()
    graph.add_node(data["root"])

    for edge in data["edges"]:
        if edge["target"] is not None:
            graph.add_edge(edge["source"], edge["target"])

    return graph


def graph_data(
    path, max_depth=5, max_files=100, functions=False, max_functions=300
):
    """Return the graph of what a command runs, sources, imports or links to.

    Nodes are files, edges are relationships, and unresolved edges keep
    their name with a target of None. Each file is visited once, so
    cycles end. Following stops after max_depth levels and max_files
    files, and metadata["truncated"] says when either left something
    out. Nodes and edges are sorted, so the result can be compared.
    """

    root = Path(path).resolve()
    root_kind = command_kind(root)
    nodes = {}
    edges = set()
    truncated = False

    def add_node(node_path, kind):
        info = FileInfo(str(node_path), kind, LANGUAGE_NAMES.get(kind))
        symbols = _symbols(node_path, kind)
        package = package_of(node_path)
        nodes[info.path] = {
            "id": info.path,
            "kind": info.kind,
            "language": info.language,
            "package": package,
            "symbol_count": len(symbols),
            "symbols": [symbol_data(symbol) for symbol in symbols],
            "metadata": {
                "filesystem": get_file_metadata(node_path),
                "package": package,
            },
        }

    add_node(root, root_kind)
    queue = deque([(root, root_kind, 0)])

    while queue:
        node, kind, depth = queue.popleft()

        if kind not in EXPANDABLE:
            continue

        children = _children(node, kind)

        if depth >= max_depth:
            if children:
                truncated = True

            continue

        for edge_kind, target, name, status, target_kind in children:
            if target is None:
                edges.add((str(node), None, edge_kind, status, name))
                continue

            key = str(target)

            if key not in nodes:
                if len(nodes) >= max_files:
                    truncated = True
                    continue

                add_node(target, target_kind)
                queue.append((target, target_kind, depth + 1))

            edges.add((str(node), key, edge_kind, status, name))

    if functions and root_kind == "elf":
        from xray import codemap

        try:
            cmap = codemap.code_map(root)
        except (OSError, ValueError):
            cmap = None
        table = [(f.address, f.size, f.symbol) for f in cmap.functions] if cmap is not None else None
        found = disasm_result(root, table=table) if table else disasm_result(root)
        known = {f.symbol: f for f in cmap.functions} if cmap is not None else {}
        count = 0

        def function_node(name):
            nonlocal count, truncated
            key = f"{root}:{name}"

            if key in nodes:
                return key

            if count >= max_functions:
                truncated = True
                return None

            count += 1
            nodes[key] = {
                "id": key,
                "kind": "function",
                "language": "ELF",
                "package": None,
                "symbol_count": 0,
                "symbols": [],
                "metadata": {"package": None},
            }
            mapped = known.get(name)
            if mapped is not None:
                nodes[key]["label"] = codemap._base(mapped.name) or mapped.name
                nodes[key]["metadata"].update(
                    name=mapped.name, file=mapped.file, line=mapped.line,
                    origin=codemap._origin(cmap, mapped.file)[0] if mapped.file else None,
                )

            return key

        def is_program(symbol):
            mapped = known.get(symbol)
            return bool(mapped and mapped.file and codemap._origin(cmap, mapped.file)[0] == "program")

        def rank(item):
            mapped = known.get(item[0])
            readable = codemap._base(mapped.name) if mapped else item[0]
            entry = readable in ("main", "main.main") or readable.endswith("::main")
            if mapped is None or not mapped.file:
                return (2, not entry, item[0])
            return (0 if is_program(item[0]) else 3, not entry, item[0])

        calls = found.calls if found else {}
        # Entry points and the program's own functions get nodes first; library callees use what is left.
        for caller, _callees in sorted(calls.items(), key=rank):
            if known and is_program(caller):
                function_node(caller)

        for caller, callees in sorted(calls.items(), key=rank):
            source = function_node(caller)

            if source is None:
                continue

            for callee in callees:
                if callee.endswith("@plt"):
                    name = callee[:-4]
                    target = f"import:{name}"
                    nodes.setdefault(
                        target,
                        {
                            "id": target,
                            "kind": "import",
                            "language": "ELF",
                            "package": None,
                            "symbol_count": 0,
                            "symbols": [],
                            "metadata": {"package": None},
                        },
                    )
                else:
                    name = callee
                    target = function_node(callee)

                    if target is None:
                        continue

                edges.add((source, target, "calls", "resolved", name))

    ordered = sorted(
        edges, key=lambda e: (e[0], e[2], e[1] or "", e[4] or "")
    )

    return {
        "root": str(root),
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": [
            edge_data(Edge(source, target, kind, status, name))
            for source, target, kind, status, name in ordered
        ],
        "metadata": {
            "schema_version": MODEL_SCHEMA_VERSION,
            "xray_version": __version__,
            "max_depth": max_depth,
            "max_files": max_files,
            "max_functions": max_functions,
            "truncated": truncated,
        },
    }
