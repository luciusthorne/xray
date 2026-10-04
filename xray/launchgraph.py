from pathlib import Path

from xray.entrypoints import command_kind, import_files
from xray.graph import DependencyGraph


def build_launcher_graph_info(command, max_depth=1, max_files=200):
    """Return (graph, truncated) for a command and its installed code.

    Nodes are absolute file paths. The command is the first node, and
    each non-stdlib module it imports that can be located on disk
    becomes a node with an edge from the importing file. Relative
    imports inside packages are followed too. Following stops after
    max_depth levels, and no more than max_files nodes are ever added.
    truncated is True when a file was left out because of max_files.
    Only Python files are followed.
    """

    graph = DependencyGraph()
    truncated = False

    start = Path(command).resolve()
    graph.add_node(str(start))

    seen = {start}
    frontier = [start]

    for _ in range(max_depth):
        next_frontier = []

        for path in frontier:
            if command_kind(path) != "python":
                continue

            for target in import_files(path):
                if target == path:
                    continue

                if target not in seen:
                    if len(seen) >= max_files:
                        truncated = True
                        continue

                    seen.add(target)
                    graph.add_node(str(target))
                    next_frontier.append(target)

                graph.add_edge(str(path), str(target))

        frontier = next_frontier

    return graph, truncated


def build_launcher_graph(command, max_depth=1, max_files=200):
    """Return a DependencyGraph of a command and its installed code.

    See build_launcher_graph_info, which also reports truncation.
    """

    graph, _ = build_launcher_graph_info(
        command, max_depth=max_depth, max_files=max_files
    )

    return graph


def launch_lines(command, max_depth=1, max_files=200):
    """Return the lines that describe a command's launcher code.

    One "source -> target" line per edge of the launcher graph, or a
    single line saying nothing was found. A last line says so when
    the file limit cut the graph short.
    """

    graph, truncated = build_launcher_graph_info(
        command, max_depth=max_depth, max_files=max_files
    )
    edges = sorted(graph.edges)

    if not edges:
        lines = ["No launcher code found"]
    else:
        lines = [f"{source} -> {target}" for source, target in edges]

    if truncated:
        lines.append(f"Truncated: file limit ({max_files}) reached")

    return lines
