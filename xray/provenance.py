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


def _usrmerge_aliases(path):
    """The path itself, then its other name on a merged-/usr system.

    Debian's dpkg database keeps the path a package shipped (/bin/ls) while
    the file is reached as /usr/bin/ls, and the other way round.
    """

    out = [path]
    for short in ("/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"):
        if path.startswith(short):
            out.append("/usr" + path)
        elif path.startswith("/usr" + short):
            out.append(path[4:])
    return out


def _dpkg_owner_lines(paths):
    """{queried path: package (name or name:arch)} from one dpkg-query -S call."""

    try:
        result = subprocess.run(
            ["dpkg-query", "-S", "--", *paths],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return {}
    wanted = set(paths)
    owners = {}
    for line in result.stdout.splitlines():
        if line.startswith("diversion by "):
            continue
        packages, separator, file = line.partition(": ")
        if separator and file in wanted and packages and file not in owners:
            owners[file] = packages.split(", ")[0].strip()
    return owners


def _dpkg_versions(packages):
    """{package (as given): "name version"} from one dpkg-query -W call."""

    packages = sorted(set(packages))
    if not packages:
        return {}
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f", "${binary:Package} ${Package} ${Version}\n", "--", *packages],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return {}
    versions = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3:
            qualified, name, version = parts
            versions[qualified] = versions[name] = f"{name} {version}"
    return {package: versions[package] for package in packages if package in versions}


def _dpkg_owners(paths):
    """{path: ("dpkg", "name version")} for the paths a dpkg package owns."""

    if shutil.which("dpkg-query") is None:
        return {}
    aliases = {path: _usrmerge_aliases(path) for path in paths}
    lines = _dpkg_owner_lines(sorted({alias for names in aliases.values() for alias in names}))
    owner = {}
    for path, names in aliases.items():
        found = next((lines[name] for name in names if name in lines), None)
        if found:
            owner[path] = found
    versions = _dpkg_versions(owner.values())
    return {path: ("dpkg", versions[package]) for path, package in owner.items() if package in versions}


def _dpkg_package(path):
    found = _dpkg_owners([path])
    return found[path][1] if path in found else None


def package_of(path):
    """Return the installed package that owns a file, or None.

    RPM systems return name-version-release.arch. Pacman and dpkg (Debian,
    Ubuntu) systems return ``name version``. Unowned files return None.
    """

    resolved = str(Path(path).resolve())
    return _rpm_package(resolved) or _pacman_package(resolved) or _dpkg_package(resolved)


def package_manager(path):
    """Return the installed package manager that owns a file, if known."""
    resolved = str(Path(path).resolve())
    if _rpm_package(resolved):
        return "rpm"
    if _pacman_package(resolved):
        return "pacman"
    if _dpkg_package(resolved):
        return "dpkg"
    return None


def packages_of(paths):
    """Return {path: (manager, "name version")} for files owned by a package.

    One package-manager call covers every path. Paths are used as
    given (resolve them first). Unowned files, and systems without rpm,
    pacman or dpkg, are simply left out.
    """

    paths = [str(path) for path in paths]
    if not paths:
        return {}

    if shutil.which("rpm") is not None:
        owned = _rpm_owners(paths)
        if owned:
            return owned

    if shutil.which("pacman") is not None:
        owned = _pacman_owners(paths)
        if owned:
            return owned

    return _dpkg_owners(paths)


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
