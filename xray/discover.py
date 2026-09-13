import shutil
from pathlib import Path


def resolve_target(target: str) -> Path | None:
    """
    Resolve a command name or filesystem path.
    """

    path = Path(target).expanduser()

    if path.exists():
        return path.resolve()

    executable = shutil.which(target)

    if executable is None:
        return None

    return Path(executable).resolve()
