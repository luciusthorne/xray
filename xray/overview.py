from pathlib import Path

from .calls import calls_lines
from .chain import chain_lines
from .entrypoints import command_kind
from .launchgraph import launch_lines
from .shellscan import scan_shell

NO_COMMANDS_NOTE = (
    "Note: no external commands found by static reading "
    "(commands run through variables or eval are not visible)"
)


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
        return calls_lines(path)

    if kind == "python" and path.suffix != ".py":
        return ["Launcher code:", *launch_lines(path)]

    return []
