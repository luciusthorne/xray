import sys
from pathlib import Path

from .discover import resolve_target
from .identify import identify_file, get_file_metadata
from .classify import detect_shebang
from .analyze import analyze_python
from .graph import DependencyGraph


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


def build_graph(workspace_root, path):
    graph = DependencyGraph()

    path = Path(path).resolve()

    # Build the graph from the directory containing the target.
    #
    # Examples:
    #
    # test_programs/cycle_a.py
    # -> test_programs/
    #
    # xray/dependencies.py
    # -> xray/
    project_root = path.parent

    graph.build_project(
        project_root,
        analyze_python,
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


def main():
    if len(sys.argv) == 1:
        print_help()
        sys.exit(1)

    if sys.argv[1] in ("--help", "-h"):
        print_help()
        return

    command = sys.argv[1]

    query = sys.argv[2] if len(sys.argv) >= 3 else None
    path_target = None

    if query == "--path":
        if len(sys.argv) != 4:
            print("Usage: xray <target> --path <target>")
            sys.exit(1)

        path_target = sys.argv[3]

    valid_queries = {
        None,
        "--deps",
        "--dependents",
        "--tree",
        "--impact",
        "--cycles",
        "--depth",
        "--project",
        "--components",
        "--reachable",
        "--reverse-reachable",
        "--path",
    }

    if query not in valid_queries:
        print("Unknown option:", query)
        print_help()
        sys.exit(1)

    print("XRAY")
    print("────────────────────────────")

    path = resolve_target(command)

    if path is None:
        print(f"Command not found: {command}")
        sys.exit(1)

    workspace_root = Path.cwd()

    file_type = identify_file(path)
    metadata = get_file_metadata(path)
    shebang = detect_shebang(path)

    analysis = None

    if file_type.startswith("Python"):
        analysis = analyze_python(path)

    graph = build_graph(
        workspace_root,
        path,
    )

    source_node = str(
        Path(path).resolve().relative_to(workspace_root)
    )

    # ---------------------------------------------------------
    # --deps
    # ---------------------------------------------------------

    if query == "--deps":
        print()
        print(f"Dependencies of {source_node}")
        print("────────────────────────────")

        dependencies = graph.dependencies_of(source_node)

        if dependencies:
            for dependency in dependencies:
                print(f"- {dependency}")
        else:
            print("none")

        return

    # ---------------------------------------------------------
    # --dependents
    # ---------------------------------------------------------

    if query == "--dependents":
        print()
        print(f"Dependents of {source_node}")
        print("────────────────────────────")

        dependents = graph.dependents_of(source_node)

        if dependents:
            for dependent in dependents:
                print(f"- {dependent}")
        else:
            print("none")

        return

    # ---------------------------------------------------------
    # --tree
    # ---------------------------------------------------------

    if query == "--tree":
        print()
        print(f"Dependency tree for {source_node}")
        print("────────────────────────────")

        for line in graph.dependency_tree(source_node):
            print(line)

        return

    # ---------------------------------------------------------
    # --impact
    # ---------------------------------------------------------

    if query == "--impact":
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

        return

    # ---------------------------------------------------------
    # --cycles
    # ---------------------------------------------------------

    if query == "--cycles":
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

        return

    # ---------------------------------------------------------
    # --depth
    # ---------------------------------------------------------

    if query == "--depth":
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

        return

    # ---------------------------------------------------------
    # --project
    # ---------------------------------------------------------

    if query == "--project":
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

        return

    # ---------------------------------------------------------
    # --components
    # ---------------------------------------------------------

    if query == "--components":
        print()
        print("Strongly connected components")
        print("────────────────────────────")

        components = graph.strongly_connected_components()

        for component in components:
            print("- " + ", ".join(component))

        return

    # ---------------------------------------------------------
    # --reachable
    # ---------------------------------------------------------

    if query == "--reachable":
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

        return

    # ---------------------------------------------------------
    # --reverse-reachable
    # ---------------------------------------------------------

    if query == "--reverse-reachable":
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

        return

    # ---------------------------------------------------------
    # --path
    # ---------------------------------------------------------

    if query == "--path":
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

        return

    # ---------------------------------------------------------
    # Default output
    # ---------------------------------------------------------

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


if __name__ == "__main__":
    main()
