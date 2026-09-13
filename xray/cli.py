import sys
from pathlib import Path

from .discover import resolve_target
from .identify import identify_file, get_file_metadata
from .classify import detect_shebang
from .analyze import analyze_python
from .graph import DependencyGraph


def main():
    usage = (
        "Usage: xray <target> "
        "[--deps|--dependents|--tree|--impact|--chains|--cycles|--project|--depth]"
    )

    if len(sys.argv) == 2 and sys.argv[1] in ("--help", "-h"):
        print("XRAY")
        print("────────────────────────────")
        print()
        print("Usage")
        print("────────────────────────────")
        print(usage)
        print()
        print("Options")
        print("────────────────────────────")
        print("-h, --help      Show this help message")
        print("--deps          Show direct dependencies")
        print("--dependents    Show direct dependents")
        print("--tree          Show dependency tree")
        print("--impact        Show files affected by removal")
        print("--chains        Show impact chains")
        print("--cycles        Show circular dependencies")
        print("--project       Show project statistics and graph")
        print("--depth         Show dependency depth")
        return

    if len(sys.argv) not in (2, 3):
        print(usage)
        sys.exit(1)

    command = sys.argv[1]
    query = sys.argv[2] if len(sys.argv) == 3 else None

    valid_queries = (
        None,
        "--deps",
        "--dependents",
        "--tree",
        "--impact",
        "--chains",
        "--cycles",
        "--project",
        "--depth",
    )

    if query not in valid_queries:
        print(f"Unknown option: {query}")
        print(usage)
        sys.exit(1)

    print("XRAY")
    print("────────────────────────────")

    path = resolve_target(command)

    if path is None:
        print(f"Command not found: {command}")
        sys.exit(1)

    file_type = identify_file(path)
    metadata = get_file_metadata(path)
    shebang = detect_shebang(path)

    analysis = None
    graph = DependencyGraph()

    if file_type.startswith("Python"):
        analysis = analyze_python(path)

    workspace_root = Path.cwd()

    if analysis:
        if path.parent.name == "test_programs":
            project_root = path.parent
        else:
            project_root = workspace_root / "xray"

        graph.build_project(
            project_root,
            analyze_python,
            workspace_root,
        )

    source_node = str(
        path.resolve().relative_to(workspace_root)
    )

    if query == "--depth":
        print()
        print(f"Dependency depth for {source_node}")
        print("────────────────────────────")

        depth = graph.dependency_depth(source_node)

        print(f"Depth: {depth}")

        return

    if query == "--project":
        print()
        print("Project")
        print("────────────────────────────")
        print(f"Root:        {project_root}")
        print(f"Nodes:       {graph.node_count()}")
        print(f"Edges:       {graph.edge_count()}")

        print()
        print("Statistics")
        print("────────────────────────────")

        leaf_nodes = graph.leaf_nodes()
        most_depended_on = graph.most_depended_on()
        cycle_count = graph.cycle_count()

        print(f"Python files:      {graph.node_count()}")
        print(f"Dependency edges:  {graph.edge_count()}")
        print(f"Leaf files:        {len(leaf_nodes)}")

        if most_depended_on:
            if len(most_depended_on) == 1:
                print(f"Most depended-on:  {most_depended_on[0]}")
            else:
                print("Most depended-on:")
                for node in most_depended_on:
                    print(f"                   {node}")
        else:
            print("Most depended-on:  none")

        print(f"Cycles:            {cycle_count}")

        print()
        print("Dependency hotspots")
        print("────────────────────────────")

        hotspots = graph.dependency_hotspots()

        if hotspots:
            for node, count in hotspots:
                print(f"- {node}: {count} dependent")
        else:
            print("none")

        print()
        print("Leaf files")
        print("────────────────────────────")

        if leaf_nodes:
            for node in leaf_nodes:
                print(f"- {node}")
        else:
            print("none")

        print()
        print("Dependency graph")
        print("────────────────────────────")

        if graph.edges:
            for source, target in graph.edges:
                print(f"- {source} → {target}")
        else:
            print("none")

        print()
        print("Circular dependencies")
        print("────────────────────────────")

        cycles = graph.find_cycles()

        if cycles:
            for cycle in cycles:
                print(f"- {' → '.join(cycle)}")
        else:
            print("none")

        return

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

    if query == "--tree":
        print()
        print(f"Dependency tree for {source_node}")
        print("────────────────────────────")

        tree = graph.dependency_tree(source_node)

        for line in tree:
            print(line)

        return

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

        return

    if query == "--chains":
        print()
        print(f"Impact chains for {source_node}")
        print("────────────────────────────")

        chains = graph.impact_chains(source_node)

        if chains:
            for chain in chains:
                print(" → ".join(chain))
        else:
            print("none")

        return

    if query == "--cycles":
        print()
        print("Circular dependencies")
        print("────────────────────────────")

        cycles = graph.find_cycles()

        if cycles:
            for cycle in cycles:
                print(f"- {' → '.join(cycle)}")
        else:
            print("none")

        return

    print(f"Target:     {command}")
    print(f"Executable: {path}")
    print(f"Type:       {file_type}")

    print()
    print("Metadata")
    print("────────────────────────────")
    print(f"Size:        {metadata['size']} bytes")
    print(f"Permissions: {metadata['mode']}")
    print(f"Owner UID:   {metadata['owner_uid']}")
    print(f"Group GID:   {metadata['group_gid']}")
    print(f"Modified:    {metadata['modified']}")

    print()
    print("Program")
    print("────────────────────────────")

    if shebang:
        print(f"Interpreter: {shebang}")
    else:
        print("Interpreter: none detected")

    if analysis:
        print()
        print("Source")
        print("────────────────────────────")
        print(f"Language:    {analysis['language']}")

        print()
        print("Imports")
        print("────────────────────────────")

        if analysis["imports"]:
            for item in analysis["imports"]:
                if item.get("name"):
                    if item["alias"]:
                        print(
                            f"- from {item['module']} "
                            f"import {item['name']} as {item['alias']}"
                        )
                    else:
                        print(
                            f"- from {item['module']} "
                            f"import {item['name']}"
                        )
                else:
                    if item["alias"]:
                        print(
                            f"- import {item['module']} "
                            f"as {item['alias']}"
                        )
                    else:
                        print(
                            f"- import {item['module']}"
                        )
        else:
            print("none")

        print()
        print("Dependencies")
        print("────────────────────────────")

        if analysis["dependencies"]:
            for item in analysis["dependencies"]:
                if item["name"]:
                    dependency = (
                        f"{item['module']}.{item['name']}"
                    )
                else:
                    dependency = item["module"]

                print(
                    f"- {command} → "
                    f"{dependency} "
                    f"[{item['type']}]"
                )
        else:
            print("none")

        print()
        print("Graph")
        print("────────────────────────────")
        print(f"Nodes: {sorted(graph.nodes)}")
        print(f"Edges: {graph.edges}")

        print()
        print("Functions")
        print("────────────────────────────")

        if analysis["functions"]:
            for item in analysis["functions"]:
                print(
                    f"- {item['name']}() "
                    f"line {item['line']}"
                )
        else:
            print("none")

        print()
        print("Classes")
        print("────────────────────────────")

        if analysis["classes"]:
            for item in analysis["classes"]:
                print(
                    f"- {item['name']} "
                    f"line {item['line']}"
                )
        else:
            print("none")

        print()
        print("Variables")
        print("────────────────────────────")

        if analysis["variables"]:
            for item in analysis["variables"]:
                print(
                    f"- {item['name']} "
                    f"line {item['line']}"
                )
        else:
            print("none")

        print()
        print("Calls")
        print("────────────────────────────")

        if analysis["calls"]:
            for item in analysis["calls"]:
                print(
                    f"- {item['name']}() "
                    f"line {item['line']}"
                )
        else:
            print("none")


if __name__ == "__main__":
    main()
