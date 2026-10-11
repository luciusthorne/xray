from collections import deque
from pathlib import Path

from . import __version__
from . import command_analyzers, python_analyzer  # noqa: F401  (register analyzers)
from .analyzers import registry
from .entrypoints import command_kind, import_files
from .errors import XRAYError
from .provenance import package_of

EXPANDABLE = ("python", "shell", "elf")


def _symbol_count(path, kind):
    if kind not in ("python", "shell"):
        return 0

    analyzer = registry.analyzer_for(path)

    if analyzer is None:
        return 0

    try:
        return len(analyzer.symbols(path))
    except XRAYError:
        return 0


def _children(path, kind):
    """Return (edge kind, target, name, status, target kind) tuples.

    target is a Path when the relationship resolved and None when not.
    """

    found = []

    if kind == "python":
        for target in import_files(path):
            found.append(
                ("imports", target, target.name, "resolved", command_kind(target))
            )

        return found

    analyzer = registry.analyzer_for(path)

    if analyzer is None:
        return found

    for edge in analyzer.edges(path):
        if edge.status != "resolved" or edge.target is None:
            found.append((edge.kind, None, edge.name, edge.status, None))
            continue

        target = Path(edge.target)
        target_kind = (
            "library" if edge.kind == "links" else command_kind(target)
        )
        found.append((edge.kind, target, edge.name, "resolved", target_kind))

    return found


def graph_data(path, max_depth=5, max_files=100):
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
        nodes[str(node_path)] = {
            "id": str(node_path),
            "kind": kind,
            "package": package_of(node_path),
            "symbol_count": _symbol_count(node_path, kind),
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

    ordered = sorted(
        edges, key=lambda e: (e[0], e[2], e[1] or "", e[4] or "")
    )

    return {
        "root": str(root),
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": [
            {
                "source": source,
                "target": target,
                "kind": kind,
                "status": status,
                "name": name,
            }
            for source, target, kind, status, name in ordered
        ],
        "metadata": {
            "xray_version": __version__,
            "max_depth": max_depth,
            "max_files": max_files,
            "truncated": truncated,
        },
    }
