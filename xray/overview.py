from pathlib import Path

from .calls import calls_lines
from .entrypoints import command_kind
from .launchgraph import launch_lines


def overview_lines(path):
    """Return lines that describe what a command is made of.

    Shell scripts and ELF binaries show what they run or link to.
    Python commands without a .py suffix (launchers) show the
    installed code they import. Other files give an empty list.
    """

    path = Path(path)
    kind = command_kind(path)

    if kind in ("shell", "elf"):
        return calls_lines(path)

    if kind == "python" and path.suffix != ".py":
        return ["Launcher code:", *launch_lines(path)]

    return []
