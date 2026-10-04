import sys
from pathlib import Path

from xray.entrypoints import command_kind, find_module_file, python_imports
from xray.graph import DependencyGraph


def _installed_targets(path):
    """Return the files of non-stdlib modules a Python file imports.

    Modules that cannot be located are skipped. Each file appears
    once, in a stable order.
    """

    targets = {}

    for module in python_imports(path):
        if module.partition(".")[0] in sys.stdlib_module_names:
            continue

        origin = find_module_file(module)

        if origin is not None:
            targets[origin.resolve()] = None

    return list(targets)


def build_launcher_graph(command, max_depth=1, max_files=50):
    """Return a DependencyGraph of a command and its installed code.

    Nodes are absolute file paths. The command is the first node, and
    each non-stdlib module it imports that can be located on disk
    becomes a node with an edge from the importing file. Following
    stops after max_depth levels, and no more than max_files nodes
    are ever added. Only Python files are followed.
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

            for target in _installed_targets(path):
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
