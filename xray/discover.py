import shutil
from pathlib import Path

from .libresolve import find_library


def resolve_target(target: str) -> Path | None:
    """
    Resolve a command name or filesystem path.
    """

    path = Path(target).expanduser()

    if path.exists():
        return path.resolve()

    executable = shutil.which(target)

    if executable is not None:
        return Path(executable).resolve()

    # Allow installed shared libraries to be used as CLI targets.
    library = find_library(target)

    if library is not None:
        return library

    return None
