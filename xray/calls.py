from pathlib import Path

from xray.command_analyzers import ShellAnalyzer
from xray.elfscan import ElfScan, scan_elf
from xray.entrypoints import command_kind
from xray.libresolve import find_library, ldconfig_cache
from xray.locate import locate as _locate


def _section(title, items):
    return [title, *items] if items else [title, "none"]


def _shell_lines(path):
    analyzer = ShellAnalyzer()
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

    return (
        _section("Functions:", functions)
        + _section("Sources:", sources)
        + _section("Commands:", commands)
    )


def _elf_lines(path, max_imports):
    scan = scan_elf(path)

    if scan == ElfScan():
        return ["No ELF information found (is readelf installed?)"]

    cache = ldconfig_cache()
    libraries = []

    for name in scan.needed:
        found = find_library(name, cache)

        if found is None:
            libraries.append(f"- {name} -> not found")
        else:
            libraries.append(f"- {name} -> {found}")

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


def calls_lines(path, max_imports=20):
    """Return the lines that describe what a command runs or links to.

    Shell scripts list their functions, sourced files and commands.
    ELF binaries list their interpreter, the shared libraries they
    need (with the file each resolves to) and the symbols they import,
    capped at max_imports. Other files get a single explanatory line.
    """

    kind = command_kind(path)

    if kind == "shell":
        return _shell_lines(path)

    if kind == "elf":
        return _elf_lines(path, max_imports)

    return [
        f"Not a shell script or binary ({kind}): "
        "--calls reads shell scripts and ELF binaries only"
    ]
