"""Text views of the static-analysis results.

Each function returns the lines to print for one file, so the CLI only
prints them. Results come from static analysis of the source, so names
used dynamically are not seen.
"""

from pathlib import Path

from xray.callgraph import build_call_graph
from xray.complexity import analyze_complexity
from xray.coupling import calculate_call_coupling, calculate_coupling
from xray.references import find_references
from xray.relationships import find_relationships
from xray.symbols import extract_symbols
from xray.unused import find_unused_imports
from xray.unused_symbols import find_unused_symbols


def _project_root(path):
    return Path(path).resolve().parent


def _target(item):
    if item.target:
        return f" => {item.target}"

    return ""


def _qualified(symbol):
    if symbol.parent:
        return f"{symbol.parent}.{symbol.name}"

    return symbol.name


def symbols_lines(path):
    symbols = extract_symbols(path)

    if not symbols:
        return ["none"]

    return [
        f"- {symbol.kind}: {_qualified(symbol)} (line {symbol.line})"
        for symbol in symbols
    ]


def references_lines(path):
    references = find_references(path, _project_root(path))

    if not references:
        return ["none"]

    return [
        f"- {reference.name} (line {reference.line}): "
        f"{reference.status}{_target(reference)}"
        for reference in references
    ]


def relationships_lines(path):
    relationships = find_relationships(path, _project_root(path))

    if not relationships:
        return ["none"]

    return [
        f"- {item.kind}: {item.source} -> {item.name} "
        f"(line {item.line}): {item.status}{_target(item)}"
        for item in relationships
    ]


def unused_lines(path):
    unused = find_unused_imports(path)

    if not unused:
        return ["none"]

    lines = []

    for item in unused:
        line = f"- {item.name} (line {item.line})"

        if item.module and item.module != item.name:
            line += f", from {item.module}"

        lines.append(line)

    lines.append("")
    lines.append(
        "Static analysis result, not proof: dynamic use is not detected."
    )

    return lines


def complexity_lines(path):
    metrics = analyze_complexity(path)
    functions = sorted(
        metrics.functions,
        key=lambda item: (-item.complexity, item.name),
    )

    max_complexity = max((item.complexity for item in functions), default=0)
    max_nesting = max((item.nesting for item in functions), default=0)

    lines = [
        f"Lines of code:      {metrics.lines_of_code}",
        f"Functions:          {len(functions)}",
        f"Classes:            {metrics.class_count}",
        f"Maximum complexity: {max_complexity}",
        f"Maximum nesting:    {max_nesting}",
        "",
        "Functions (most complex first)",
    ]

    if not functions:
        lines.append("- none")

    for item in functions:
        lines.append(
            f"- {item.name}: complexity {item.complexity}, "
            f"nesting {item.nesting}, {item.lines} lines "
            f"(line {item.line})"
        )

    return lines


COUPLING_LIMIT = 10


def _value(item, name):
    value = getattr(item, name)

    if callable(value):
        return value()

    return value


def _format(value):
    if isinstance(value, float):
        return f"{value:.2f}"

    return str(value)


def call_graph_lines(call_graph, file_name):
    prefix = f"{file_name}:"
    nodes = sorted(node for node in call_graph.nodes if node.startswith(prefix))

    if not nodes:
        return ["none"]

    lines = []

    for node in nodes:
        lines.append(node)

        for callee in call_graph.callees_of(node):
            lines.append(f"  -> {callee}")

        for name, status in call_graph.unresolved_from(node):
            lines.append(f"  ? {name} ({status})")

    lines.append("")
    lines.append("Calls that cannot be resolved statically are marked with ?.")

    return lines


def callgraph_lines(path):
    resolved = Path(path).resolve()
    call_graph = build_call_graph(resolved.parent)

    return call_graph_lines(call_graph, resolved.name)


def unused_symbols_lines(path):
    symbols = find_unused_symbols(_project_root(path))

    if not symbols:
        return ["none"]

    ordered = sorted(
        symbols,
        key=lambda symbol: (symbol.file, symbol.line, symbol.name),
    )

    lines = [
        f"- {symbol.kind}: {_qualified(symbol)} "
        f"({symbol.file}, line {symbol.line})"
        for symbol in ordered
    ]

    lines.append("")
    lines.append(
        "Static analysis result, not proof: dynamic use and "
        "external APIs are not detected."
    )

    return lines


def _describe_module(module):
    return (
        f"{module.module}: fan-in {len(module.incoming)}, "
        f"fan-out {len(module.outgoing)}"
    )


def coupling_lines(graph, source_node):
    project = calculate_coupling(graph)
    modules = list(project.modules)

    if not modules:
        return ["none"]

    lines = [
        f"Modules:      {_format(_value(project, 'module_count'))}",
        f"Edges:        {_format(_value(project, 'edge_count'))}",
        f"Density:      {_format(_value(project, 'density'))}",
        f"Max fan-in:   {_format(_value(project, 'max_fan_in'))}",
        f"Max fan-out:  {_format(_value(project, 'max_fan_out'))}",
    ]

    mine = [module for module in modules if module.module == source_node]

    if mine:
        lines.append("")
        lines.append(f"This file: {_describe_module(mine[0])}")

    ranked = sorted(
        modules,
        key=lambda module: (
            -(len(module.incoming) + len(module.outgoing)),
            module.module,
        ),
    )
    shown = ranked[:COUPLING_LIMIT]

    lines.append("")
    lines.append(
        f"Most coupled modules (top {len(shown)} of {len(modules)})"
    )
    lines.extend(f"- {_describe_module(module)}" for module in shown)

    return lines


def call_coupling_lines(path):
    call_graph = build_call_graph(_project_root(path))
    items = list(calculate_call_coupling(call_graph))

    if not items:
        return ["none"]

    ranked = sorted(
        items,
        key=lambda item: (-(item.calls_out + item.calls_in), item.module),
    )
    shown = ranked[:COUPLING_LIMIT]

    lines = [
        f"Modules: {len(items)}",
        "",
        f"Most call-coupled modules (top {len(shown)} of {len(items)})",
    ]
    lines.extend(
        f"- {item.module}: calls out {item.calls_out}, "
        f"calls in {item.calls_in}"
        for item in shown
    )

    return lines
