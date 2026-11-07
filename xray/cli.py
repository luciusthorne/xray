import json
import shlex
import sys
from contextlib import redirect_stdout
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from . import __version__
from .analysis_views import (
    call_coupling_lines,
    callgraph_lines,
    complexity_lines,
    coupling_lines,
    references_lines,
    relationships_lines,
    unused_lines,
    unused_symbols_lines,
)
from .analyze import analyze_python
from .classify import detect_shebang
from .discover import resolve_target
from .entrypoints import command_kind
from .errors import CLIError, TargetError, XRAYError
from .export import export_data
from .graph import DependencyGraph
from .identify import get_file_metadata, identify_file
from .overview import overview_lines
from .shellmetrics import shell_metrics_lines
from .sourcelookup import remove_source_cache, source_cache_entries
from .verbs import is_verb, run_verb


def print_help():
    print("Usage: xray <target> [option] [option arguments]")
    print("       xray inspect <command> [--trace] [--json]")
    print("       xray why <command> <file, command, library or package> [--json]")
    print()
    print("Evidence graph (every link shows its proof: observed, declared, inferred, guessed):")
    print("  xray inspect <command>        What it reaches: commands, libraries, packages, blind spots")
    print("  xray inspect <command> --trace -- <args>  Also run it and show what static reading missed")
    print("  xray why <command> <target>   The proof chain from the command to a target")
    print()
    print("Start with a command overview, then inspect its code or execution chain:")
    print("  xray <command> --report")
    print("  xray <command> --chain")
    print("  xray <command> --code")
    print()
    print("Options by topic:")
    print("Code:")
    print("  --report [--md]        Identity, overview, and available source files")
    print("  --inspect [--md]       Same unified command inspection as --report")
    print("  --code [name] [--asm]  Read source; ELF lists DWARF names or disassembles")
    print("  --browse               Terminal menu: overview, functions and their code, calls, chain")
    print("  --source <function>    Show C source via local tree, debuginfod, or RPM/DNF")
    print("                         XRAY_SOURCE_PATH searches existing source trees first")
    print("  --source-cache-list    List cached source packages and their sizes")
    print("  --source-cache-remove <package>  Remove one cached source package")
    print("  --source-cache-clear   Remove all cached source packages")
    print("                         XRAY_SOURCE_CACHE_MAX_MIB sets an optional size limit")
    print("  --disasm-function <n>  Show one function of an ELF binary, annotated (needs rizin)")
    print()
    print("Binaries:")
    print("  --uses                 Show what an ELF binary can do, grouped by purpose")
    print("  --disasm               Show which functions an ELF binary calls (reads objdump)")
    print("  --trace                Run the command and show what it executes and opens")
    print("  --package              Show the package that owns a command")
    print("  --toolchain            Show the language, compiler, and bundled modules of an ELF binary")
    print("  --serve                Open a local page: click a function for its source and disassembly")
    print()
    print("Scripts:")
    print("  --calls                Show what a script or binary runs or imports")
    print("  --chain                Show the tree of what a command runs")
    print("  --launch               Show installed code a launcher runs")
    print("  --launch-depth <n>     Same, following imports n levels deep")
    print("  --launch-limit <n>     Same, 3 levels deep, at most n files")
    print("  --shell-metrics        Show shell script functions and complexity")
    print("                         Python, Ruby, JavaScript, Lua, TypeScript and C summaries are in --report")
    print()
    print("Graph:")
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
    print("  --changes [<base>]     Show Git changes and affected project files")
    print()
    print("Python:")
    print("  --symbols              Show symbols recognized by the file's analyzer")
    print("  --references           Show where names are used and what they resolve to")
    print("  --relationships        Show calls and other symbol relationships")
    print("  --unused               Show imports that appear unused")
    print("  --complexity           Show function complexity and nesting")
    print("  --callgraph [function] Which function calls which (Python, shell, C/C++/Rust/Go binaries)")
    print("  --unused-symbols       Show definitions that appear unused (whole folder)")
    print("  --coupling             Show fan-in and fan-out of modules")
    print("  --call-coupling        Show calls in and out of each module")
    print()
    print("Export:")
    print("  --json                 Export file metadata, symbols, and relationships as JSON")
    print("  --graph-json           Export graph nodes, symbols, metadata, and edges as JSON")
    print("  --html                 Print an interactive graph page (save it with >)")
    print("  <query> ... --json     Print any text query as structured JSON")
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
    print()
    print("Ruby/JavaScript parser results and downloaded source packages are cached.")
    print("Set XRAY_CACHE or XDG_CACHE_HOME to choose the cache location.")
    print()
    print("Examples:")
    print("  xray pytest --report --md > pytest.md")
    print("  xray pytest --chain")
    print("  xray pytest --code")
    print("  xray pytest --trace -- --version")
    print("  xray pytest --graph-json > pytest-graph.json")


def build_graph(workspace_root, path):
    path = Path(path).resolve()
    project_root = path.parent
    from .project_graph import build_project_graph

    return build_project_graph(project_root, workspace_root)


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

    from .entrypoints import command_kind as _ck

    if _ck(context.path) in ("shell", "elf", "perl"):
        from .commandproject import resolve_target_node

        target_node = resolve_target_node(path_target)

        if target_node is None:
            raise TargetError(f"Target not found: {path_target}")
    else:
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

    from .entrypoints import command_kind as _ck

    if _ck(context.path) in ("shell", "elf", "perl"):
        from .commandproject import project_lines

        print()

        for line in project_lines(graph):
            print(line)

        return

    print()
    print("Project")
    print("────────────────────────────")

    from collections import Counter

    from .entrypoints import command_kind as _kind
    from .model import LANGUAGE_NAMES

    languages = Counter(
        _kind(context.workspace_root / node)
        for node in graph.nodes
    )
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

    if set(languages) <= {"python"}:
        print(f"Python files:      {len(graph.nodes)}")
    else:
        print(f"Source files:      {len(graph.nodes)}")
        print("Languages:         " + ", ".join(
            f"{LANGUAGE_NAMES.get(kind, kind)} {count}"
            for kind, count in sorted(languages.items())
        ))
    print(f"Dependency edges:  {dependency_edges}")
    for title, references in (
        ("External dependencies", graph.external_edges),
        ("Unresolved dependencies", graph.unresolved_edges),
    ):
        if references:
            print(f"{title}: {len(references)}")
            for source, kind, name in references[:10]:
                print(f"- {source}: {name} [{kind}]")
            if len(references) > 10:
                print(f"- ... and {len(references) - 10} more")
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


def query_changes(context):
    from .git_analysis import changes_since
    from .project_graph import build_project_graph

    base = sys.argv[3] if len(sys.argv) > 3 else "HEAD"
    try:
        root, changes = changes_since(context.path, base)
    except (OSError, ValueError) as error:
        raise TargetError(f"Git change analysis failed: {error}") from error

    print()
    print(f"Git changes in {root} compared with {base}")
    print("────────────────────────────")

    if not changes:
        print("No changed or untracked files.")
        return

    for change in changes:
        if change.previous_path:
            print(f"{change.status:>4}  {change.previous_path} → {change.path}")
        else:
            print(f"{change.status:>4}  {change.path}")

    graph = build_project_graph(root, root)
    changed_nodes = {change.path for change in changes}
    affected_by = {}

    for change in changes:
        for dependent in graph.reverse_reachable_from(change.path):
            if dependent not in changed_nodes:
                affected_by.setdefault(dependent, set()).add(change.path)

    print()
    print("Affected project files")
    print("────────────────────────────")
    if affected_by:
        for path in sorted(affected_by)[:30]:
            causes = ", ".join(sorted(affected_by[path]))
            print(f"- {path} (depends on {causes})")
        if len(affected_by) > 30:
            print(f"- ... and {len(affected_by) - 30} more")
    else:
        print("No current in-project dependents found.")


QUERIES["--project"] = query_project
QUERIES["--changes"] = query_changes


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


def query_package(context):
    path = context.path
    source_node = context.source_node

    from xray.provenance import package_of

    package = package_of(path)

    print()
    print(f"Package of {source_node}")
    print("────────────────────────────")
    print(package if package else "Not owned by any installed package")


QUERIES["--package"] = query_package


def query_toolchain(context):
    from xray.entrypoints import command_kind
    from xray.fingerprint import toolchain_lines

    if command_kind(context.path) != "elf":
        raise CLIError("--toolchain requires an ELF binary target")

    print()
    print(f"Toolchain of {context.source_node}")
    print("────────────────────────────")

    for line in toolchain_lines(context.path):
        print(line)


QUERIES["--toolchain"] = query_toolchain


def query_trace(context):
    path = context.path
    source_node = context.source_node

    from xray.trace import trace_lines

    args = sys.argv[4:] if len(sys.argv) > 3 else []
    lines = trace_lines(path, args)

    print()
    print(f"Trace of {source_node}")
    print("────────────────────────────")

    for line in lines:
        print(line)


QUERIES["--trace"] = query_trace


def _require_elf(context, option):
    if command_kind(context.path) != "elf":
        raise CLIError(f"{option} requires an ELF binary target")


def query_disasm(context):
    _require_elf(context, "--disasm")
    from xray.disasm import disasm_lines

    print()
    print(f"Disassembly calls of {context.source_node}")
    print("────────────────────────────")

    for line in disasm_lines(context.path):
        print(line)


QUERIES["--disasm"] = query_disasm


def query_report(context):
    from xray.report import report_lines

    markdown = len(sys.argv) == 4
    if markdown:
        print(f"# Report: {context.source_node}")
    else:
        print()
        print(f"Report of {context.source_node}")
        print("════════════════════════════")
    for line in report_lines(context.path, markdown):
        print(line)


def query_inspect(context):
    """Present the existing report as a unified code inspection."""

    from xray.report import report_lines

    markdown = len(sys.argv) == 4
    if markdown:
        print(f"# Inspection: {context.source_node}")
    else:
        print()
        print(f"Inspection of {context.source_node}")
        print("════════════════════════════")

    for line in report_lines(context.path, markdown):
        print(line)


QUERIES["--inspect"] = query_inspect


QUERIES["--report"] = query_report


def query_code(context):
    from xray.codeview import code_lines

    args = sys.argv[3:]
    asm = "--asm" in args
    names = [a for a in args if a != "--asm"]
    name = names[0] if names else None
    print()
    print(f"Code view of {name or 'available code'} in {context.source_node}")
    print("────────────────────────────")
    for line in code_lines(
        context.path, name, asm, say=lambda t: print(t, file=sys.stderr)
    ):
        print(line)


QUERIES["--code"] = query_code


def query_source(context):
    _require_elf(context, "--source")
    from xray.sourcelookup import files_lines, source_lines

    name = sys.argv[3] if len(sys.argv) > 3 else None
    say = lambda t: print(t, file=sys.stderr)
    print()
    print(f"Source of {name or 'all files'} in {context.source_node}")
    print("────────────────────────────")
    if name and not name.endswith((".c", ".h")):
        lines = source_lines(context.path, name, say=say)
    else:
        lines = files_lines(context.path, name, say=say)
    for line in lines:
        print(line)


QUERIES["--source"] = query_source


def query_disasm_function(context):
    _require_elf(context, "--disasm-function")
    from xray.rizinview import function_lines

    name = sys.argv[3]

    print()
    print(f"Function {name} of {context.source_node}")
    print("────────────────────────────")

    for line in function_lines(context.path, name):
        print(line)


QUERIES["--disasm-function"] = query_disasm_function


def query_uses(context):
    _require_elf(context, "--uses")
    from xray.uses import uses_lines

    print()
    print(f"Uses of {context.source_node}")
    print("────────────────────────────")

    for line in uses_lines(context.path):
        print(line)


QUERIES["--uses"] = query_uses


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

    from xray.provenance import package_of

    package = package_of(path)

    if package:
        print(f"Package:    {package}")

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

    print()
    print("Explore this command")
    print("────────────────────────────")
    target = shlex.quote(context.command)
    print(f"  xray {target} --report       Full overview and source files")
    print(f"  xray {target} --code          Read source code")
    print(f"  xray {target} --calls         Imports and commands it references")
    print(f"  xray {target} --chain         Follow its command or import chain")
    print(f"  xray {target} --deps          Show project dependencies")
    print(f"  xray {target} --cycles        Find dependency cycles")
    print(f"  xray {target} --path <target> Find a dependency path")
    print(f"  xray {target} --json          Export structured analysis")


QUERIES[None] = query_default


def print_view(title, lines):
    print()
    print(title)
    print("────────────────────────────")

    for line in lines:
        print(line)


def query_symbols(context):
    from . import command_analyzers, python_analyzer  # noqa: F401
    from .analyzers import registry

    analyzer = registry.analyzer_for(context.path)

    if analyzer is None:
        raise TargetError(f"No symbol analyzer for {context.file_type}: {context.path}")

    symbols = analyzer.symbols(context.path)
    lines = [
        f"- {symbol.line}: {symbol.kind} {symbol.qualified_name}"
        for symbol in symbols
    ]
    print_view(f"Symbols in {context.source_node}", lines or ["none"])


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
    if command_kind(context.path) == "elf":
        from xray.codemap import elf_callgraph

        args = sys.argv[3:]
        focus = args[0] if args else None
        print(f"Building the code map and reading calls of {context.path.name}", file=sys.stderr)
        lines = elf_callgraph(context.path, focus)
        if lines is None:
            raise TargetError(f"No function names in {context.path} (stripped, and no debuginfod debug file)")
        print_view(f"Call graph of {context.path.name}" + (f": {focus}" if focus else ""), lines)
        return
    if command_kind(context.path) == "shell":
        from xray.scriptgraph import callgraph_lines as shell_callgraph_lines
        from xray.scriptgraph import shell_graph

        args = sys.argv[3:]
        graph = shell_graph(context.path)
        if graph is None:
            raise TargetError(f"Could not parse {context.path} as a shell script")
        print_view(f"Call graph of {context.path.name}" + (f": {args[0]}" if args else ""),
                   shell_callgraph_lines(graph, context.path.name, args[0] if args else None))
        return
    if command_kind(context.path) == "lisp":
        from xray.scriptgraph import callgraph_lines as lisp_callgraph_lines
        from xray.scriptgraph import lisp_graph

        args = sys.argv[3:]
        graph = lisp_graph(context.path)
        if graph is None:
            raise TargetError(f"No Lisp forms read from {context.path}")
        print_view(f"Call graph of {context.path.name}" + (f": {args[0]}" if args else ""),
                   lisp_callgraph_lines(graph, context.path.name, args[0] if args else None))
        return
    if command_kind(context.path) in ("perl", "ruby", "javascript", "typescript", "lua"):
        from xray.scriptgraph import callgraph_lines as script_callgraph_lines
        from xray.scriptgraph import symbol_graph

        args = sys.argv[3:]
        graph = symbol_graph(context.path, command_kind(context.path))
        if graph is None:
            raise TargetError(f"No functions found in {context.path}")
        print_view(f"Call graph of {context.path.name}" + (f": {args[0]}" if args else "")
                   + " (calls found by name)",
                   script_callgraph_lines(graph, context.path.name, args[0] if args else None))
        return
    if sys.argv[3:]:
        raise CLIError("--callgraph FUNCTION is for compiled programs and scripts; for Python use: xray <file> --callgraph")
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


def query_json(context):
    print(
        json.dumps(
            export_data(context.path),
            indent=2,
            sort_keys=True,
        )
    )


QUERIES["--json"] = query_json


def query_graph_json(context):
    from xray.graphjson import graph_data

    print(
        json.dumps(
            graph_data(context.path, functions=True),
            indent=2,
            sort_keys=True,
        )
    )


QUERIES["--graph-json"] = query_graph_json


def query_html(context):
    from xray.graphjson import graph_data
    from xray.html import render_html

    print(render_html(graph_data(context.path, functions=True)), end="")


QUERIES["--html"] = query_html


def query_browse(context):
    from xray.browse import browse

    if not sys.stdin.isatty():
        raise CLIError(
            "--browse needs an interactive terminal; use --inspect, --code, or --serve"
        )

    browse(context.path)


QUERIES["--browse"] = query_browse


def query_serve(context):
    from xray.entrypoints import command_kind
    from xray.serve import serve

    if command_kind(context.path) not in (
        "elf", "shell", "perl", "ruby", "javascript", "lua", "typescript", "c", "python", "lisp"
    ):
        raise TargetError("--serve reads ELF, shell, Perl, Ruby, JavaScript, Lua, TypeScript, C, Python and Lisp commands")

    serve(context.path)


QUERIES["--serve"] = query_serve
QUERIES["--unused-symbols"] = query_unused_symbols
QUERIES["--coupling"] = query_coupling
QUERIES["--call-coupling"] = query_call_coupling


COMMAND_GRAPH_QUERIES = frozenset(
    (
        "--tree",
        "--deps",
        "--dependents",
        "--impact",
        "--cycles",
        "--depth",
        "--components",
        "--reachable",
        "--reverse-reachable",
        "--path",
        "--project",
        "--coupling",
    )
)


def run():
    self_target = len(sys.argv) == 1

    if self_target:
        # With no target, inspect XRAY's own CLI implementation. This gives
        # the user a useful self-overview instead of an error.
        sys.argv.append("xray")

    if sys.argv[1] == "--source-cache-list":
        if len(sys.argv) != 2:
            raise CLIError("--source-cache-list takes no arguments")
        entries = source_cache_entries()
        if not entries:
            print("No downloaded source packages are cached.")
        else:
            for name, size in entries:
                print(f"{name}\t{size} bytes")
            print(f"Total: {sum(size for _, size in entries)} bytes")
        return

    if sys.argv[1] == "--source-cache-remove":
        if len(sys.argv) != 3:
            raise CLIError("usage: xray --source-cache-remove <package>")
        try:
            remove_source_cache(sys.argv[2])
        except (OSError, ValueError) as error:
            raise CLIError(str(error)) from error
        print(f"Removed cached source package: {sys.argv[2]}")
        return

    if sys.argv[1] == "--source-cache-clear":
        if len(sys.argv) != 2:
            raise CLIError("--source-cache-clear takes no arguments")
        try:
            removed = remove_source_cache()
        except (OSError, ValueError) as error:
            raise CLIError(str(error)) from error
        print(f"Removed {removed} cached source package(s).")
        return

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

    elif query == "--disasm-function":
        if len(sys.argv) != 4:
            raise CLIError(
                "Usage: xray <command> --disasm-function <name>"
            )

    elif query == "--source":
        if len(sys.argv) not in (3, 4):
            raise CLIError("Usage: xray <command> --source [<function or file>]")

    elif query == "--changes":
        if len(sys.argv) > 4 or (len(sys.argv) == 4 and sys.argv[3].startswith("-")):
            raise CLIError("Usage: xray <file in repo> --changes [<base-ref>]")

    elif query == "--code":
        rest = [a for a in sys.argv[3:] if a != "--asm"]
        if len(rest) > 1 or len(sys.argv) > 5:
            raise CLIError("Usage: xray <command> --code [<function or file>] [--asm]")

    elif query == "--callgraph":
        if len(sys.argv) > 4 or (len(sys.argv) == 4 and sys.argv[3].startswith("-")):
            raise CLIError("Usage: xray <command> --callgraph [<function>]")

    elif query in ("--report", "--inspect"):
        if len(sys.argv) > 4 or (len(sys.argv) == 4 and sys.argv[3] != "--md"):
            raise CLIError("Usage: xray <command> --report [--md]")

    elif query == "--trace":
        if len(sys.argv) > 3 and sys.argv[3] != "--":
            raise CLIError(
                "Usage: xray <command> --trace [-- <args>]"
            )

    elif len(sys.argv) > 3:
        raise CLIError(
            f"Unexpected argument: {sys.argv[3]}"
        )

    path = resolve_target(command)

    if self_target and (path is None or path.is_dir()):
        path = Path(__file__).resolve()
        try:
            command = str(path.relative_to(Path.cwd().resolve()))
        except ValueError:
            command = str(path)

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

    from .entrypoints import command_kind as _kind

    on_command = (
        query in COMMAND_GRAPH_QUERIES
        and not (
            query == "--project"
            and _kind(path) not in ("shell", "elf", "perl")
        )
        and (
            _kind(path) in ("shell", "elf", "perl", "ruby", "javascript", "lua", "typescript", "c", "lisp")
            or (_kind(path) == "python" and path.suffix != ".py")
        )
    )

    if on_command:
        from .graphjson import command_graph

        graph = command_graph(path)
    elif query in COMMAND_GRAPH_QUERIES:
        graph = build_graph(
            workspace_root,
            path,
        )
    else:
        graph = DependencyGraph()

    source_node = str(
        Path(path).resolve().relative_to(workspace_root)
    )

    if on_command:
        source_node = str(Path(path).resolve())

    if query in PYTHON_ONLY_QUERIES and analysis is None and not (
        query == "--callgraph"
        and command_kind(Path(path)) in ("elf", "shell", "perl", "ruby", "javascript", "typescript", "lua", "lisp")
    ):
        raise TargetError(f"Not a Python file: {path}")

    show_banner = query not in ("--json", "--graph-json", "--html", "--serve", "--browse") and not (
        query in ("--report", "--inspect") and len(sys.argv) == 4
    )

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

    if show_banner:
        output = StringIO()
        with redirect_stdout(output):
            QUERIES[query](context)
        print("XRAY")
        print("────────────────────────────")
        sys.stdout.write(output.getvalue())
    else:
        QUERIES[query](context)

# Queries whose output is already a document; --json cannot follow them.
NOT_JSON_CONVERTIBLE = frozenset(["--json", "--graph-json", "--html", "--serve", "--browse"])


def _json_modifier():
    """True when argv ends with --json after a text query."""

    args = sys.argv

    if len(args) < 4 or args[-1] != "--json" or args[2] not in QUERIES:
        return False

    if "--" in args[3:-1]:
        return False  # --json belongs to the traced command's arguments

    if args[2] in NOT_JSON_CONVERTIBLE:
        raise CLIError(f"{args[2]} cannot be combined with --json")

    if "--md" in args:
        raise CLIError("--md and --json cannot be combined")

    return True


def run_json():
    """Run a text query and print its output as structured JSON."""

    import json

    from .textjson import text_to_data

    query, target = sys.argv[2], sys.argv[1]
    sys.argv.pop()
    output = StringIO()

    with redirect_stdout(output):
        run()

    data = text_to_data(output.getvalue().splitlines(), query, target)
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main():
    try:
        if is_verb(sys.argv[1:]):
            return run_verb(sys.argv[1:])
        if _json_modifier():
            run_json()
        else:
            run()
    except XRAYError as error:
        print(f"Error: {error}", file=sys.stderr)
        return error.exit_code

    return 0


if __name__ == "__main__":
    sys.exit(main())
