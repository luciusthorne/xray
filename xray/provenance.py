import subprocess
from pathlib import Path

_FORMAT = "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"


def package_of(path):
    """Return the installed package that owns a file, or None.

    Asks rpm about the resolved path and gives name-version-release.arch.
    A file owned by several packages gives the first one. A file that no
    package owns, or a system without rpm, gives None.
    """

    resolved = str(Path(path).resolve())

    try:
        result = subprocess.run(
            ["rpm", "-qf", "--qf", _FORMAT, resolved],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        if line.strip():
            return line.strip()

    return None
