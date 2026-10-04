import shutil
from pathlib import Path


def locate(name):
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
