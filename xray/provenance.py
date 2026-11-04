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


def packages_of(paths):
    """Return {path: (manager, "name version")} for files owned by a package.

    One package-manager call covers every path. Paths are used as
    given (resolve them first). Unowned files, and systems without rpm
    or pacman, are simply left out.
    """

    paths = [str(path) for path in paths]
    if not paths:
        return {}

    if shutil.which("rpm") is not None:
        owned = _rpm_owners(paths)
        if owned:
            return owned

    if shutil.which("pacman") is not None:
        return _pacman_owners(paths)

    return {}


_OWNER_FORMAT = "%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n"


def _rpm_owners(paths):
    """Ask rpm once; it prints one line per path, in order."""

    try:
        result = subprocess.run(
            ["rpm", "-qf", "--qf", _OWNER_FORMAT, "--", *paths],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return {}

    lines = result.stdout.splitlines()
    if len(lines) != len(paths):
        # A file owned by several packages prints several lines: ask one by one.
        lines = []
        for path in paths:
            single = subprocess.run(
                ["rpm", "-qf", "--qf", _OWNER_FORMAT, "--", path],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            lines.append(single.stdout.splitlines()[0] if single.returncode == 0 and single.stdout else "")

    owned = {}
    for path, line in zip(paths, lines):
        line = line.strip()
        if line and " is not owned by " not in line and not line.startswith("error:"):
            owned[path] = ("rpm", line)
    return owned


def _pacman_owners(paths):
    try:
        result = subprocess.run(
            ["pacman", "-Qo", "--", *paths],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return {}

    owned = {}
    wanted = set(paths)
    for line in result.stdout.splitlines():
        file, separator, owner = line.rpartition(" is owned by ")
        if separator and file in wanted and owner.strip():
            owned[file] = ("pacman", owner.strip())
    return owned
