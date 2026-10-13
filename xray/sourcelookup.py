import os
import re
import shlex
import subprocess
import tarfile
import tempfile
from pathlib import Path

from xray.entrypoints import command_kind
from xray.minidebug import read_function_table

VARIANT = re.compile(r"(\.(isra|constprop|part|cold|lto_priv)(\.\d+)?)+$")


def base_name(name):
    """Strip compiler suffixes such as .isra.0 or .cold: they are not in source."""

    return VARIANT.sub("", name)


def cache_root():
    return Path(os.environ.get("XRAY_CACHE", Path.home() / ".cache" / "xray")) / "src"


def find_definition(root, name, max_lines=120):
    """Find a C function definition under root.

    Returns (file, first line number, lines, others) or None. Matches a
    name at the start of a line followed by "(", and only if a "{" at
    column 0 comes before any ";" (so prototypes are skipped). The
    line above is included when it holds the return type. others counts
    further matches in other places.
    """

    pattern = re.compile(rf"^{re.escape(name)}\s*\(")
    found = []

    for folder, _dirs, files in os.walk(root):
        for filename in sorted(files):
            if not filename.endswith((".c", ".h")):
                continue

            path = Path(folder) / filename

            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for index, line in enumerate(lines):
                if not pattern.match(line):
                    continue

                end = _body_end(lines, index)

                if end is not None:
                    found.append((path, index, end, lines))

    if not found:
        return None

    path, index, end, lines = found[0]
    start = index

    if index > 0:
        above = lines[index - 1].rstrip()

        if above and not above.startswith(("#", "}", "/")) and not above.endswith((";", "*/")):
            start = index - 1

    shown = lines[start : end + 1]

    if len(shown) > max_lines:
        shown = shown[:max_lines] + [f"... and {len(shown) - max_lines} more lines"]

    return path, start + 1, shown, len(found) - 1


def _body_end(lines, index):
    opened = False

    for j in range(index, min(index + 2000, len(lines))):
        line = lines[j]

        if not opened:
            if line.startswith("{"):
                opened = True
            elif line.rstrip().endswith(";"):
                return None
        elif line.startswith("}"):
            return j

    return None


def _query(path):
    try:
        result = subprocess.run(
            ["rpm", "-qf", "--qf", r"%{NAME}-%{VERSION}-%{RELEASE}\n%{SOURCERPM}\n", str(path)],
            capture_output=True, text=True, errors="replace", check=False,
        )
    except OSError:
        return None

    parts = result.stdout.split()

    if result.returncode != 0 or len(parts) < 2 or parts[1] == "(none)":
        return None

    return parts[0], parts[1][:-4] if parts[1].endswith(".rpm") else parts[1]


def ensure_source(nvr, stem, say):
    """Return the unpacked source folder for a package, downloading once."""

    target = cache_root() / stem

    if (target / ".done").is_file():
        return target

    say(f"Downloading source package for {nvr} (cached afterwards)")

    with tempfile.TemporaryDirectory() as work:
        subprocess.run(
            ["dnf", "download", "--source", nvr, "--destdir", work],
            capture_output=True, text=True, check=True, timeout=300,
        )
        srpms = list(Path(work).glob("*.src.rpm"))

        if not srpms:
            raise FileNotFoundError("no source package was downloaded")

        subprocess.run(
            f"rpm2cpio {shlex.quote(str(srpms[0]))} | cpio -idm",
            shell=True, cwd=work, capture_output=True, check=True, timeout=300,
        )
        tarballs = [
            p for p in Path(work).glob("*.tar.*")
            if not p.name.endswith((".sig", ".asc"))
        ]

        if not tarballs:
            raise FileNotFoundError("the source package holds no tarball")

        target.mkdir(parents=True, exist_ok=True)

        with tarfile.open(max(tarballs, key=lambda p: p.stat().st_size)) as archive:
            archive.extractall(target, filter="data")

    (target / ".done").write_text("ok\n", encoding="utf-8")

    return target


def source_lines(path, name, say=lambda text: None, max_lines=120):
    """Return the C source of a function of an installed binary.

    The package comes from rpm, its source package is downloaded once
    into the cache, and the definition is searched by name. The code
    is upstream code: Fedora patches may make it differ from what is
    installed.
    """

    path = Path(path)

    if command_kind(path) != "elf":
        return ["Not an ELF binary: --source reads ELF only"]

    known = {entry[2] for entry in read_function_table(path)}
    plain = base_name(name)

    if known and name not in known and plain not in {base_name(n) for n in known}:
        return [f"Unknown function: {name[:60]} (see --disasm for names)"]

    info = _query(path.resolve())

    if info is None:
        return ["No installed package owns this file, so there is no source package"]

    nvr, stem = info

    try:
        root = ensure_source(nvr, stem, say)
    except FileNotFoundError as error:
        return [f"Source not available: {error}"]
    except (OSError, subprocess.SubprocessError) as error:
        return [f"Could not fetch the source package: {error}"]

    result = find_definition(root, plain, max_lines)

    if result is None:
        return [f"No definition of {plain} found in the source of {nvr}"]

    file, line, shown, others = result
    header = [f"{file.relative_to(root)}:{line}"]

    if plain != name:
        header.append(f"({name} is a compiler variant of {plain})")

    if others:
        header.append(f"({others} more match(es) elsewhere; showing the first)")

    return header + shown
