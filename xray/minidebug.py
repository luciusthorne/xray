import lzma
import os
import re
import subprocess
import tempfile
from pathlib import Path

from xray.entrypoints import command_kind

_FUNC = re.compile(
    r"^\s*\d+:\s+[0-9a-fA-F]+\s+\S+\s+FUNC\s+\w+\s+\w+\s+(\S+)\s+(\S+)"
)


def parse_functions(text):
    """Return the sorted, unique names of functions defined in readelf -s text."""

    names = set()

    for line in text.splitlines():
        match = _FUNC.match(line)

        if not match or match.group(1) == "UND":
            continue

        name = match.group(2).split("@", 1)[0]

        if name:
            names.add(name)

    return tuple(sorted(names))


def read_minidebuginfo(path, timeout=10):
    """Return the function names kept in a stripped ELF file.

    Some distributions (Fedora among them) leave a small compressed
    symbol table in the .gnu_debugdata section of stripped binaries.
    It is read through objcopy and readelf, on temporary files, and
    the binary itself is never modified. A file that is not ELF, has
    no such section, or any failure gives an empty tuple. Only
    function names are available: no lines, no bodies.
    """

    path = Path(path)

    if command_kind(path) != "elf":
        return ()

    env = dict(os.environ)
    env["LC_ALL"] = "C"

    try:
        with tempfile.TemporaryDirectory() as folder:
            section = Path(folder) / "section"

            subprocess.run(
                [
                    "objcopy",
                    "--dump-section",
                    f".gnu_debugdata={section}",
                    str(path),
                    str(Path(folder) / "out"),
                ],
                capture_output=True,
                env=env,
                timeout=timeout,
                check=False,
            )

            if not section.is_file():
                return ()

            try:
                data = lzma.decompress(section.read_bytes())
            except (lzma.LZMAError, EOFError):
                return ()

            symbols = Path(folder) / "symbols"
            symbols.write_bytes(data)
            result = subprocess.run(
                ["readelf", "-sW", str(symbols)],
                capture_output=True,
                text=True,
                errors="replace",
                env=env,
                timeout=timeout,
                check=False,
            )
    except (OSError, subprocess.SubprocessError):
        return ()

    return parse_functions(result.stdout)
