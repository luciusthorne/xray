from pathlib import Path

from .calls import calls_lines
from .chain import chain_lines
from .elfscan import ElfScan, scan_elf
from .entrypoints import command_kind
from .libresolve import find_library, ldconfig_cache
from .minidebug import read_minidebuginfo
from .provenance import package_of
from .uses import uses_summary
from .launchgraph import launch_lines
from .shellscan import scan_shell

NO_COMMANDS_NOTE = (
    "Note: no external commands found by static reading "
    "(commands run through variables or eval are not visible)"
)


MAX_LIBRARIES = 15
MAX_FUNCTIONS = 15


def _elf_overview(path):
    scan = scan_elf(path)

    if scan == ElfScan():
        return calls_lines(path)

    cache = ldconfig_cache() if scan.needed else {}
    libraries = []

    for name in scan.needed[:MAX_LIBRARIES]:
        found = find_library(name, cache)

        if found is None:
            libraries.append(f"- {name} -> not found")
            continue

        package = package_of(found)
        suffix = f" ({package})" if package else ""
        libraries.append(f"- {name} -> {found}{suffix}")

    hidden = len(scan.needed) - MAX_LIBRARIES

    if hidden > 0:
        libraries.append(f"- ... and {hidden} more")

    interpreter = [f"- {scan.interpreter}"] if scan.interpreter else ["none"]
    libraries = libraries or ["none"]

    lines = [
        "Interpreter:",
        *interpreter,
        "Libraries:",
        *libraries,
        f"Imports: {len(scan.imports)} (use --calls to list them)",
    ]

    summary = uses_summary(scan.imports)

    if summary:
        lines.append(summary)

    functions = read_minidebuginfo(path)

    if functions:
        lines.append(f"Functions ({len(functions)}):")
        lines.extend(f"- {name}" for name in functions[:MAX_FUNCTIONS])
        hidden = len(functions) - MAX_FUNCTIONS

        if hidden > 0:
            lines.append(f"- ... and {hidden} more")

    return lines


def overview_lines(path):
    """Return lines that describe what a command is made of.

    Shell scripts and ELF binaries show what they run or link to.
    A shell script with no visible external commands gets a note, so
    "none" is not mistaken for "runs nothing". Python commands without
    a .py suffix (launchers) show the installed code they import.
    Other files give an empty list.
    """

    path = Path(path)
    kind = command_kind(path)

    if kind == "shell":
        lines = calls_lines(path)

        if not scan_shell(path).commands:
            lines = [*lines, NO_COMMANDS_NOTE]

        chain = chain_lines(
            path, max_depth=2, max_files=15, include_libraries=False
        )

        if len(chain) > 1:
            lines = [*lines, "Chain:", *chain]

        return lines

    if kind == "elf":
        return _elf_overview(path)

    if kind == "python" and path.suffix != ".py":
        return ["Launcher code:", *launch_lines(path)]

    return []
