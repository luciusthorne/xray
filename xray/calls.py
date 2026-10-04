import shutil
from pathlib import Path

from xray.elfscan import ElfScan, scan_elf
from xray.entrypoints import command_kind
from xray.libresolve import find_library, ldconfig_cache
from xray.shellscan import scan_shell


def _locate(name):
    """Return the resolved file a command name refers to, or None.

    Names without a slash are looked up on PATH only, never in the
    current directory.
    """

    if "/" in name:
        path = Path(name).expanduser()
        found = path if path.is_file() else None
    else:
        found = shutil.which(name)

    if found is None:
        return None

    return Path(found).resolve()


def _section(title, items):
    return [title, *items] if items else [title, "none"]


def _shell_lines(path):
    scan = scan_shell(path)
    commands = []

    for name in scan.commands:
        target = _locate(name)

        if target is None:
            commands.append(f"- {name} -> not found")
        else:
            commands.append(
                f"- {name} -> {target} [{command_kind(target)}]"
            )

    return (
        _section("Functions:", [f"- {n}" for n in scan.functions])
        + _section("Sources:", [f"- {n}" for n in scan.sources])
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
