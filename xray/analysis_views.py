"""Text views of the static-analysis results.

Each function returns the lines to print for one file, so the CLI only
prints them. Results come from static analysis of the source, so names
used dynamically are not seen.
"""

from pathlib import Path

from xray.complexity import analyze_complexity
from xray.references import find_references
from xray.relationships import find_relationships
from xray.symbols import extract_symbols
from xray.unused import find_unused_imports


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
