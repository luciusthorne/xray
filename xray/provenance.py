import shutil
import subprocess
from pathlib import Path

_FORMAT = "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"


def _rpm_package(path):
    if shutil.which("rpm") is None:
        return None

    try:
        result = subprocess.run(
            ["rpm", "-qf", "--qf", _FORMAT, path],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    return next((line.strip() for line in result.stdout.splitlines() if line.strip()), None)


def _pacman_package(path):
    if shutil.which("pacman") is None:
        return None

    try:
        owner = subprocess.run(
            ["pacman", "-Qoq", "--", path],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return None

    name = owner.stdout.strip()
    if owner.returncode != 0 or not name:
        return None

    try:
        version = subprocess.run(
            ["pacman", "-Q", name],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return None

    if version.returncode != 0:
        return None

    return next((line.strip() for line in version.stdout.splitlines() if line.strip()), None)


def package_of(path):
    """Return the installed package that owns a file, or None.

    RPM systems return name-version-release.arch. Pacman systems return
    the package manager's ``name version`` line. Unowned files return None.
    """

    resolved = str(Path(path).resolve())
    return _rpm_package(resolved) or _pacman_package(resolved)


def package_manager(path):
    """Return the installed package manager that owns a file, if known."""
    resolved = str(Path(path).resolve())
    if _rpm_package(resolved):
        return "rpm"
    if _pacman_package(resolved):
        return "pacman"
    return None
