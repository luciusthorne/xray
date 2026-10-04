import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .discover import resolve_target
from .overview import overview_lines
from .entrypoints import command_kind
from .shellmetrics import shell_metrics_lines
from .identify import identify_file, get_file_metadata
from .classify import detect_shebang
from .analyze import analyze_python
from .graph import DependencyGraph
from .errors import XRAYError, CLIError, TargetError
from .analysis_views import (
    call_coupling_lines,
    callgraph_lines,
    complexity_lines,
    coupling_lines,
    references_lines,
    relationships_lines,
    symbols_lines,
    unused_lines,
    unused_symbols_lines,
)



def print_help():
    print("Usage: xray <target> [options]")
    print()
    print("Options:")
    print("  --deps                 Show dependencies")
    print("  --dependents           Show dependents")
    print("  --tree                 Show dependency tree")
    print("  --impact               Show impact analysis")
    print("  --cycles               Show circular dependencies")
    print("  --depth                Show dependency depth")
    print("  --project              Show project statistics")
    print("  --components           Show strongly connected components")
    print("  --reachable            Show reachable dependencies")
    print("  --reverse-reachable    Show reverse reachable dependents")
    print("  --path <target>        Show dependency path to target")
    print("  --launch               Show installed code a launcher runs")
    print("  --launch-depth <n>     Same, following imports n levels deep")
    print("  --launch-limit <n>     Same, 3 levels deep, at most n files")
    print("  --calls                Show what a script or binary runs")
    print("  --chain                Show the tree of what a command runs")
    print("  --symbols              Show functions, classes and methods")
    print("  --references           Show where names are used and what they resolve to")
    print("  --relationships        Show calls and other symbol relationships")
    print("  --unused               Show imports that appear unused")
    print("  --complexity           Show function complexity and nesting")
    print("  --callgraph            Show which functions each function calls")
    print("  --unused-symbols       Show definitions that appear unused (whole folder)")
    print("  --coupling             Show fan-in and fan-out of modules")
    print("  --call-coupling        Show calls in and out of each module")
    print("  --shell-metrics        Show shell script functions and complexity")
    print()
    print("Other:")
    print("  --version, -V          Show the version")
    print("  --help, -h             Show this help")
    print()
    print("Exit codes:")
    print("  0  success")
    print("  1  general error or unexpected crash")
    print("  2  invalid command-line usage")
    print("  3  target or file error")
    print("  4  analysis error")


def build_graph(workspace_root, path):
    graph = DependencyGraph()

    path = Path(path).resolve()
    project_root = path.parent

    graph.build_project(
        project_root,
        analyze_python,
        workspace_root,
    )

    shebang = detect_shebang(path)

    if path.suffix != ".py" and shebang:
        if "python" in shebang.lower():
            graph.build_from(
                path,
                analyze_python,
                project_root,
                workspace_root,
            )
    return graph


def dependency_depth(graph, node):
    """
    Return the maximum dependency depth.

    Cycles are handled without infinite recursion.
    """

    def walk(current, path):
        dependencies = graph.dependencies_of(current)

        if not dependencies:
            return len(path) - 1

        longest = len(path) - 1

        for dependency in dependencies:
            if dependency in path:
                longest = max(longest, len(path))
                continue

            depth = walk(
                dependency,
                path + [dependency],
            )

            longest = max(longest, depth)

        return longest

    return walk(node, [node])


@dataclass
class QueryContext:
    command: str
    query: str | None
    path: Path
    path_target: str | None
    workspace_root: Path
    file_type: str
    metadata: Any
    shebang: Any
    analysis: Any
    graph: Any
    source_node: str


QUERIES = {}


def query_components(context):
    graph = context.graph

    print()
    print("Strongly connected components")
    print("────────────────────────────")

    components = graph.strongly_connected_components()

    for component in components:
        print("- " + ", ".join(component))


QUERIES["--components"] = query_components


def query_reachable(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print(
        f"Reachable dependencies from {source_node}"
    )
    print("────────────────────────────")

    reachable = graph.reachable_from(source_node)

    if reachable:
        for node in reachable:
            print(f"- {node}")
    else:
        print("- none")


QUERIES["--reachable"] = query_reachable


def query_reverse_reachable(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print(
        f"Reverse-reachable dependents of "
        f"{source_node}"
    )
    print("────────────────────────────")

    reachable = graph.reverse_reachable_from(
        source_node
    )

    if reachable:
        for node in reachable:
            print(f"- {node}")
    else:
        print("- none")


QUERIES["--reverse-reachable"] = query_reverse_reachable


def query_dependents(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print(f"Dependents of {source_node}")
    print("────────────────────────────")

    dependents = graph.dependents_of(source_node)

    if dependents:
        for dependent in dependents:
            print(f"- {dependent}")
    else:
        print("none")


QUERIES["--dependents"] = query_dependents


def query_deps(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print(f"Dependencies of {source_node}")
    print("────────────────────────────")

    dependencies = graph.dependencies_of(source_node)

    if dependencies:
        for dependency in dependencies:
            print(f"- {dependency}")
    else:
        print("none")


QUERIES["--deps"] = query_deps


def query_tree(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print(f"Dependency tree for {source_node}")
    print("────────────────────────────")

    for line in graph.dependency_tree(source_node):
        print(line)


QUERIES["--tree"] = query_tree


def query_depth(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print(
        f"Dependency depth for {source_node}"
    )
    print("────────────────────────────")

    depth = dependency_depth(
        graph,
        source_node,
    )

    print(f"Depth: {depth}")


QUERIES["--depth"] = query_depth


def query_path(context):
    path_target = context.path_target
    workspace_root = context.workspace_root
    graph = context.graph
    source_node = context.source_node

    target_path = Path(path_target).resolve()

    try:
        target_node = str(
            target_path.relative_to(workspace_root)
        )
    except ValueError:
        target_node = path_target

    print()
    print(
        f"Dependency path from "
        f"{source_node} to "
        f"{target_node}"
    )
    print("────────────────────────────")

    path_result = graph.find_path(
        source_node,
        target_node,
    )

    if path_result:
        print(" → ".join(path_result))
    else:
        print("No path found")


QUERIES["--path"] = query_path


def query_impact(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print(f"Impact of removing {source_node}")
    print("────────────────────────────")

    impact = graph.impact_of(source_node)

    print()
    print("Directly affected:")

    if impact["direct"]:
        for node in impact["direct"]:
            print(f"- {node}")
    else:
        print("- none")

    print()
    print("Indirectly affected:")

    if impact["indirect"]:
        for node in impact["indirect"]:
            print(f"- {node}")
    else:
        print("- none")

    total = (
        len(impact["direct"])
        + len(impact["indirect"])
    )

    print()
    print(f"Total affected files: {total}")

    print()
    print("Impact chains")
    print("────────────────────────────")

    chains = graph.impact_chains(source_node)

    if chains:
        for chain in chains:
            print(" → ".join(chain))
    else:
        print("none")


QUERIES["--impact"] = query_impact


def query_project(context):
    graph = context.graph

    print()
    print("Project")
    print("────────────────────────────")

    python_files = len(graph.nodes)
    dependency_edges = len(graph.edges)

    components = graph.strongly_connected_components()

    cycle_count = 0

    for component in components:
        if len(component) > 1:
            cycle_count += 1

        elif component:
            node = component[0]

            if node in graph.dependencies_of(node):
                cycle_count += 1

    leaf_files = sum(
        1
        for node in graph.nodes
        if not graph.dependencies_of(node)
    )

    print(f"Python files:      {python_files}")
    print(f"Dependency edges:  {dependency_edges}")
    print(f"Leaf files:        {leaf_files}")
    print(f"Cycles:            {cycle_count}")

    print()
    print("Dependency hotspots")

    hotspot_counts = []

    for node in graph.nodes:
        count = len(
            graph.dependents_of(node)
        )

        if count > 0:
            hotspot_counts.append(
                (node, count)
            )

    hotspot_counts.sort(
        key=lambda item: (-item[1], item[0])
    )

    if hotspot_counts:
        for node, count in hotspot_counts:
            print(f"- {node}: {count}")
    else:
        print("- none")


QUERIES["--project"] = query_project


def query_cycles(context):
    graph = context.graph
    source_node = context.source_node

    print()
    print("Circular dependencies")
    print("────────────────────────────")

    components = graph.strongly_connected_components()

    cycles = []

    for component in components:
        if len(component) > 1:
            if source_node in component:
                cycles.append(component)

        elif component:
            node = component[0]

            if (
                node == source_node
                and node in graph.dependencies_of(node)
            ):
                cycles.append(component)

    if cycles:
        for cycle in cycles:
            if len(cycle) == 1:
                print(
                    f"{cycle[0]} → {cycle[0]}"
                )
                continue

            start = source_node
            current = start
            path = [start]
            visited = {start}

            while True:
                next_node = None

                for candidate in sorted(
                    graph.dependencies_of(current)
                ):
                    if candidate in cycle:
                        next_node = candidate
                        break

                if next_node is None:
                    break

                path.append(next_node)

                if next_node == start:
                    break

                if next_node in visited:
                    break

                visited.add(next_node)
                current = next_node

            print(" → ".join(path))
    else:
        print("none")


QUERIES["--cycles"] = query_cycles


def query_calls(context):
    path = context.path
    source_node = context.source_node

    from xray.calls import calls_lines

    print()
    print(f"Calls of {source_node}")
    print("────────────────────────────")

    for line in calls_lines(path):
        print(line)


QUERIES["--calls"] = query_calls


def query_chain(context):
    path = context.path
    source_node = context.source_node

    from xray.chain import chain_lines

    print()
    print(f"Chain of {source_node}")
    print("────────────────────────────")

    for line in chain_lines(path):
        print(line)


QUERIES["--chain"] = query_chain


def query_launch(context):
    query = context.query
    path = context.path
    source_node = context.source_node

    from xray.launchgraph import launch_lines

    depth = 1
    limit = 200

    if query == "--launch-depth":
        depth = int(sys.argv[3])
    elif query == "--launch-limit":
        depth = 3
        limit = int(sys.argv[3])

    print()
    print(f"Launcher code of {source_node}")
    print("────────────────────────────")

    for line in launch_lines(
        path, max_depth=depth, max_files=limit
    ):
        print(line)


QUERIES["--launch"] = query_launch
QUERIES["--launch-depth"] = query_launch
QUERIES["--launch-limit"] = query_launch


def query_default(context):
    path = context.path
    file_type = context.file_type
    metadata = context.metadata
    shebang = context.shebang
    analysis = context.analysis

    print()
    print(f"File:       {path}")
    print(f"Type:       {file_type}")

    if metadata:
        print(f"Size:       {metadata.get('size', 'unknown')} bytes")

    if shebang:
        print(f"Shebang:    {shebang}")

    if analysis is not None:
        print()
        print("Python analysis")
        print("────────────────────────────")

        print(
            f"Imports:    "
            f"{len(analysis['dependencies'])}"
        )

        local_dependencies = [
            dependency
            for dependency in analysis["dependencies"]
            if dependency["type"] == "local"
        ]

        print(
            f"Local deps: "
            f"{len(local_dependencies)}"
        )

    lines = overview_lines(path)

    if lines:
        print()
        print("Overview")
        print("────────────────────────────")

        for line in lines:
            print(line)


QUERIES[None] = query_default


def print_view(title, lines):
    print()
    print(title)
    print("────────────────────────────")

    for line in lines:
        print(line)


def query_symbols(context):
    print_view(
        f"Symbols in {context.source_node}",
        symbols_lines(context.path),
    )


def query_references(context):
    print_view(
        f"References in {context.source_node}",
        references_lines(context.path),
    )


def query_relationships(context):
    print_view(
        f"Relationships in {context.source_node}",
        relationships_lines(context.path),
    )


def query_unused(context):
    print_view(
        f"Unused imports in {context.source_node}",
        unused_lines(context.path),
    )


def query_complexity(context):
    print_view(
        f"Complexity of {context.source_node}",
        complexity_lines(context.path),
    )


QUERIES["--symbols"] = query_symbols
QUERIES["--references"] = query_references
QUERIES["--relationships"] = query_relationships
QUERIES["--unused"] = query_unused
QUERIES["--complexity"] = query_complexity

PYTHON_ONLY_QUERIES = {
    "--symbols",
    "--references",
    "--relationships",
    "--unused",
    "--complexity",
    "--callgraph",
    "--unused-symbols",
    "--coupling",
    "--call-coupling",
}


def query_callgraph(context):
    print_view(
        f"Call graph of {context.source_node}",
        callgraph_lines(context.path),
    )


def query_unused_symbols(context):
    print_view(
        f"Unused symbols in {context.path.parent}",
        unused_symbols_lines(context.path),
    )


def query_coupling(context):
    print_view(
        "Module coupling",
        coupling_lines(context.graph, context.source_node),
    )


def query_call_coupling(context):
    print_view(
        f"Call coupling in {context.path.parent}",
        call_coupling_lines(context.path),
    )


QUERIES["--callgraph"] = query_callgraph


def query_shell_metrics(context):
    if command_kind(context.path) != "shell":
        raise TargetError(f"Not a shell script: {context.path}")

    print_view(
        f"Shell metrics of {context.source_node}",
        shell_metrics_lines(context.path),
    )


QUERIES["--shell-metrics"] = query_shell_metrics
QUERIES["--unused-symbols"] = query_unused_symbols
QUERIES["--coupling"] = query_coupling
QUERIES["--call-coupling"] = query_call_coupling


def run():
    if len(sys.argv) == 1:
        raise CLIError("missing target")

    if sys.argv[1] in ("--help", "-h"):
        print_help()
        return

    if sys.argv[1] in ("--version", "-V"):
        print(f"xray {__version__}")
        return

    if sys.argv[1].startswith("-"):
        raise CLIError(
            f"Unknown option: {sys.argv[1]}"
        )

    command = sys.argv[1]

    query = sys.argv[2] if len(sys.argv) >= 3 else None
    path_target = None

    if query not in QUERIES:
        raise CLIError(
            f"Unknown option: {query}"
        )

    if query == "--path":
        if len(sys.argv) != 4:
            raise CLIError(
                "Usage: xray <target> --path <target>"
            )

        path_target = sys.argv[3]

    elif query in ("--launch-depth", "--launch-limit"):
        if (
            len(sys.argv) != 4
            or not sys.argv[3].isascii()
            or not sys.argv[3].isdigit()
            or int(sys.argv[3]) < 1
        ):
            raise CLIError(
                f"Usage: xray <target> {query} <number>"
            )

    elif len(sys.argv) > 3:
        raise CLIError(
            f"Unexpected argument: {sys.argv[3]}"
        )

    path = resolve_target(command)

    if path is None:
        raise TargetError(
            f"Command not found: {command}"
        )

    if path.is_dir():
        raise TargetError(
            f"Target is a directory: {path}"
        )

    workspace_root = Path.cwd()

    if not path.is_relative_to(workspace_root):
        workspace_root = path.parent

    file_type = identify_file(path)
    metadata = get_file_metadata(path)

    shebang = detect_shebang(path)

    analysis = None

    if file_type.startswith("Python") or path.suffix == ".py":
        analysis = analyze_python(path)

    graph = build_graph(
        workspace_root,
        path,
    )

    source_node = str(
        Path(path).resolve().relative_to(workspace_root)
    )

    if query in PYTHON_ONLY_QUERIES and analysis is None:
        raise TargetError(f"Not a Python file: {path}")

    print("XRAY")
    print("────────────────────────────")

    context = QueryContext(
        command=command,
        query=query,
        path=path,
        path_target=path_target,
        workspace_root=workspace_root,
        file_type=file_type,
        metadata=metadata,
        shebang=shebang,
        analysis=analysis,
        graph=graph,
        source_node=source_node,
    )

    QUERIES[query](context)

    # ---------------------------------------------------------
    # --deps
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --dependents
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --tree
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --impact
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --cycles
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --depth
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --project
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --components
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --reachable
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --reverse-reachable
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # --path
    # ---------------------------------------------------------


def main():
    try:
        run()
    except XRAYError as error:
        print(f"Error: {error}", file=sys.stderr)
        return error.exit_code

    return 0


if __name__ == "__main__":
    sys.exit(main())
