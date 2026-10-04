from pathlib import Path

from xray.entrypoints import command_kind, import_files
from xray.graph import DependencyGraph


def build_launcher_graph(command, max_depth=1, max_files=50):
    """Return a DependencyGraph of a command and its installed code.

    Nodes are absolute file paths. The command is the first node, and
    each non-stdlib module it imports that can be located on disk
    becomes a node with an edge from the importing file. Relative
    imports inside packages are followed too. Following stops after
    max_depth levels, and no more than max_files nodes are ever added.
    Only Python files are followed.
    """

    graph = DependencyGraph()

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
                        continue

                    seen.add(target)
                    graph.add_node(str(target))
                    next_frontier.append(target)

                graph.add_edge(str(path), str(target))

        frontier = next_frontier

    return graph


def launch_lines(command, max_depth=1):
    """Return the lines that describe a command's launcher code.

    One "source -> target" line per edge of the launcher graph, or a
    single line saying nothing was found.
    """

    graph = build_launcher_graph(command, max_depth=max_depth)
    edges = sorted(graph.edges)

    if not edges:
        return ["No launcher code found"]

    return [f"{source} -> {target}" for source, target in edges]
