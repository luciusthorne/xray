from pathlib import Path

# Importing analyzer modules registers them in the shared registry.
from xray import command_analyzers, python_analyzer  # noqa: F401
from xray.analyzers import registry
from xray.elfscan import ElfScan, scan_elf
from xray.entrypoints import command_kind
from xray.shellscan import scan_shell


def _section(title, items):
    return [title, *items] if items else [title, "none"]


def _shell_lines(path):
    analyzer = registry.analyzer_for(path)
    functions = [f"- {s.name}" for s in analyzer.symbols(path)]
    sources = []
    commands = []

    for edge in analyzer.edges(path):
        if edge.kind == "sources":
            sources.append(f"- {edge.name}")
        elif edge.kind == "runs":
            if edge.status != "resolved":
                commands.append(f"- {edge.name} -> not found")
            else:
                kind = command_kind(Path(edge.target))
                commands.append(f"- {edge.name} -> {edge.target} [{kind}]")

    count = scan_shell(path).dynamic
    extra = (
        [f"Commands run through variables or eval (not resolved): {count}"]
        if count
        else []
    )

    return (
        _section("Functions:", functions)
        + _section("Sources:", sources)
        + _section("Commands:", commands)
        + extra
    )


def _elf_lines(path, max_imports):
    scan = scan_elf(path)

    if scan == ElfScan():
        return ["No ELF information found (is readelf installed?)"]

    analyzer = registry.analyzer_for(path)
    resolved = {
        edge.name: edge.target
        for edge in analyzer.edges(path)
        if edge.kind == "links" and edge.status == "resolved" and edge.name
    } if analyzer is not None else {}
    libraries = [
        f"- {name} -> {resolved[name]}" if resolved.get(name)
        else f"- {name} -> not found"
        for name in scan.needed
    ]

    shown = scan.imports[:max_imports]
    imports = [f"- {name}" for name in shown]
    hidden = len(scan.imports) - len(shown)

    if hidden > 0:
        imports.append(f"- ... and {hidden} more")

    interpreter = [f"- {scan.interpreter}"] if scan.interpreter else []

    return (
        _section("Interpreter:", interpreter)
        + _section("Libraries:", libraries)
        + _section(f"Imports ({len(scan.imports)}):", imports)
    )


def _perl_lines(path):
    analyzer = registry.analyzer_for(path)
    functions = [f"- {s.name}" for s in analyzer.symbols(path)]
    modules = []

    for edge in analyzer.edges(path):
        if edge.status != "resolved":
            modules.append(f"- {edge.name} -> not found")
        else:
            kind = command_kind(Path(edge.target))
            modules.append(f"- {edge.name} -> {edge.target} [{kind}]")

    return _section("Functions:", functions) + _section("Modules:", modules)


def _ruby_lines(path):
    analyzer = registry.analyzer_for(path)
    functions = [
        f"- {symbol.kind} {symbol.name} (line {symbol.line})"
        for symbol in analyzer.symbols(path)
    ]
    imports = []

    for edge in analyzer.edges(path):
        if edge.status == "resolved":
            imports.append(f"- {edge.name} -> {edge.target}")
        else:
            imports.append(f"- {edge.name} -> not found")

    return (
        _section("Functions, classes and modules:", functions)
        + _section("Literal require calls:", imports)
        + ["Dynamic require calls are not resolved by static analysis."]
    )


def _javascript_lines(path):
    analyzer = registry.analyzer_for(path)
    symbols = [
        f"- {symbol.kind} {symbol.name} (line {symbol.line})"
        for symbol in analyzer.symbols(path)
    ]
    imports = []

    for edge in analyzer.edges(path):
        if edge.status == "resolved":
            imports.append(f"- {edge.name} -> {edge.target}")
        elif edge.status == "external":
            imports.append(f"- {edge.name} [built-in]")
        else:
            imports.append(f"- {edge.name} -> not resolved")

    return (
        _section("Functions, classes and methods:", symbols)
        + _section("Imports and literal require calls:", imports)
        + ["Computed dynamic imports and require() calls are not resolved."]
    )


def _treesitter_lines(path, kind):
    analyzer = registry.analyzer_for(path)
    symbols = [
        f"- {symbol.kind} {symbol.name} (line {symbol.line})"
        for symbol in analyzer.symbols(path)
    ]
    imports = []

    for edge in analyzer.edges(path):
        if edge.status == "resolved":
            imports.append(f"- {edge.name} -> {edge.target}")
        elif edge.status == "external":
            marker = "system header" if kind == "c" else "built-in"
            imports.append(f"- {edge.name} [{marker}]")
        else:
            imports.append(f"- {edge.name} -> not resolved")

    label = {"lua": "Lua", "typescript": "TypeScript", "c": "C"}[kind]
    return (
        _section(f"{label} symbols:", symbols)
        + _section("Literal imports:", imports)
        + [f"Dynamic {label} imports are not resolved by static analysis."]
    )


def calls_lines(path, max_imports=20):
    """Return the lines that describe what a command runs or links to.

    Shell scripts list their functions, sourced files and commands.
    Ruby and JavaScript list recognized definitions and imports. Lua,
    TypeScript, and C list recognized definitions and literal imports. Perl
    lists subroutines and loaded modules. ELF binaries list their
    interpreter, the shared libraries they
    need (with the file each resolves to) and the symbols they import,
    capped at max_imports. Other files get a single explanatory line.
    """

    kind = command_kind(path)

    # Importing these modules registers their implementations in the shared
    # registry. Views keep format-specific presentation, but consume the same
    # analyzer instances as graph export and chain traversal.
    if kind == "shell":
        return _shell_lines(path)

    if kind == "elf":
        return _elf_lines(path, max_imports)

    if kind == "perl":
        return _perl_lines(path)

    if kind == "ruby":
        return _ruby_lines(path)

    if kind == "javascript":
        return _javascript_lines(path)

    if kind in {"lua", "typescript", "c"}:
        return _treesitter_lines(path, kind)

    return [
        (
            f"Not a supported command type ({kind}): "
            "--calls reads shell, Perl, Ruby, JavaScript, Lua, TypeScript, C and ELF commands"
        )
    ]
