from pathlib import Path

from xray.entrypoints import command_kind
from xray.libresolve import find_library
from xray.locate import locate


def resolve_target_node(text):
    """Return the graph node (an absolute path) a --path target names, or None.

    A text with a slash is a path. A bare name is looked up as a command
    on PATH, then as a shared library.
    """

    if "/" in text:
        path = Path(text).expanduser()

        return str(path.resolve()) if path.exists() else None

    found = locate(text)

    if found is not None:
        return str(found)

    library = find_library(text)

    return str(library) if library else None


def _kind(node):
    if ".so" in Path(node).name:
        return "library"

    return command_kind(Path(node))


def project_lines(graph):
    """Return a report of a command graph: size, kinds, leaves, cycles, hotspots."""

    kinds = {}

    for node in graph.nodes:
        kind = _kind(node)
        kinds[kind] = kinds.get(kind, 0) + 1

    cycles = 0

    for component in graph.strongly_connected_components():
        if len(component) > 1:
            cycles += 1
        elif component and component[0] in graph.dependencies_of(component[0]):
            cycles += 1

    leaves = sum(1 for node in graph.nodes if not graph.dependencies_of(node))
    used = sorted(
        ((node, len(graph.dependents_of(node))) for node in graph.nodes),
        key=lambda item: (-item[1], item[0]),
    )
    used = [item for item in used if item[1] > 0][:10]
    by_kind = ", ".join(
        f"{kind} {count}"
        for kind, count in sorted(kinds.items(), key=lambda i: (-i[1], i[0]))
    )
    lines = [
        "Command graph",
        f"Files:  {len(graph.nodes)}",
        f"Edges:  {len(graph.edges)}",
        f"By kind:  {by_kind or 'none'}",
        f"Leaf files:  {leaves}",
        f"Cycles:  {cycles}",
        "",
        "Most used files",
    ]
    lines += [f"- {node}: {count}" for node, count in used] or ["- none"]

    return lines
