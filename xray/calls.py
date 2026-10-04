import shutil
from pathlib import Path

from xray.entrypoints import command_kind
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


def calls_lines(path):
    """Return the lines that describe what a shell script runs.

    Lists the functions it defines, the files it sources, and each
    command it invokes with the file that command resolves to and its
    kind. Files that are not shell scripts get a single explanatory
    line.
    """

    kind = command_kind(path)

    if kind != "shell":
        return [
            f"Not a shell script ({kind}): "
            "--calls reads shell scripts only"
        ]

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
