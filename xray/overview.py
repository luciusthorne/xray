from pathlib import Path

from .analyze import analyze_python
from .analyzers import plugin_kinds
from .calls import calls_lines
from .chain import chain_lines
from .elfscan import ElfScan, scan_elf
from .entrypoints import command_kind
from .launchgraph import launch_lines
from .libresolve import find_library, ldconfig_cache
from .minidebug import read_function_table
from .provenance import package_of
from .shellscan import scan_shell
from .uses import uses_summary

NO_COMMANDS_NOTE = (
    "Note: no external commands found by static reading "
    "(commands run through variables or eval are not visible)"
)


MAX_LIBRARIES = 15
MAX_FUNCTIONS = 15
MAX_PYTHON_ITEMS = 15


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

    functions = tuple(entry[2] for entry in read_function_table(path))

    if functions:
        lines.append(f"Functions ({len(functions)}):")
        lines.extend(f"- {name}" for name in functions[:MAX_FUNCTIONS])
        hidden = len(functions) - MAX_FUNCTIONS

        if hidden > 0:
            lines.append(f"- ... and {hidden} more")

    return lines


def overview_lines(path):
    """What a command is made of (see _kind_overview), plus the Electron app it runs, if any."""

    lines = _kind_overview(path)
    path = Path(path)
    if command_kind(path) in ("shell", "elf", "unknown") or path.is_dir():
        from .electron import find_app
        from .electron import overview_lines as app_lines

        app = find_app(path)
        if app is not None:
            lines = [*lines, *app_lines(app)]
    return lines


def _kind_overview(path):
    """Return lines that describe what a command is made of.

    Python source files show statically detected structure; shell scripts
    and ELF binaries show what they run or link to.
    A shell script with no visible external commands gets a note, so
    "none" is not mistaken for "runs nothing". Python commands without
    a .py suffix (launchers) show the installed code they import. Static
    call names are not runtime traces.
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

    if kind in {"perl", "ruby", "javascript", "lua", "typescript", "c", "lisp"} or kind in plugin_kinds():
        lines = calls_lines(path)
        chain = chain_lines(path, max_depth=2, max_files=15)

        if len(chain) > 1:
            lines = [*lines, "Chain:", *chain]

        return lines

    if kind == "elf":
        return _elf_overview(path)

    if kind == "python":
        if path.suffix != ".py":
            return ["Launcher code:", *launch_lines(path)]

        analysis = analyze_python(path)
        functions = [item["name"] for item in analysis["functions"]]
        classes = [item["name"] for item in analysis["classes"]]
        imports = analysis["dependencies"]
        calls = analysis["calls"]
        lines = [
            "Static Python source summary (does not execute the file):",
            f"Functions: {len(functions)}",
        ]

        if functions:
            lines.extend(f"- {name}" for name in functions[:MAX_PYTHON_ITEMS])
            hidden = len(functions) - MAX_PYTHON_ITEMS

            if hidden > 0:
                lines.append(f"- ... and {hidden} more")

        lines.append(f"Classes: {len(classes)}")

        if classes:
            lines.extend(f"- {name}" for name in classes[:MAX_PYTHON_ITEMS])
            hidden = len(classes) - MAX_PYTHON_ITEMS

            if hidden > 0:
                lines.append(f"- ... and {hidden} more")

        lines.append(f"Imports: {len(imports)}")

        if imports:
            for dependency in imports[:MAX_PYTHON_ITEMS]:
                name = dependency["module"]

                if dependency["name"]:
                    name = f"{name}.{dependency['name']}" if name else dependency["name"]

                lines.append(f"- {name or '(relative import)'} [{dependency['type']}]")

            hidden = len(imports) - MAX_PYTHON_ITEMS

            if hidden > 0:
                lines.append(f"- ... and {hidden} more")

        lines.append(f"Call sites: {len(calls)}")
        lines.append("Note: static call names do not prove which code runs at runtime.")
        return lines

    return []
