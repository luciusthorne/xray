from pathlib import Path

from xray.entrypoints import command_kind
from xray.perlscan import scan_perl
from xray.rizinview import function_lines
from xray.shellscan import function_lines as shell_function_lines
from xray.sourcelookup import files_lines, source_lines


def _numbered(lines, start=1, limit=400):
    shown = [f"{n:5d}  {line}" for n, line in enumerate(lines[:limit], start)]

    if len(lines) > limit:
        shown.append(f"... and {len(lines) - limit} more lines")

    return shown


def code_lines(path, name=None, asm=False, say=lambda text: None):
    """Return the code of a command, whatever kind it is.

    ELF binaries: source files, or the C source of a function (plus its
    disassembly with asm). Shell and Perl scripts: the script with line
    numbers, or one function from its line. Other files: the text.
    """

    path = Path(path)
    kind = command_kind(path)

    if kind == "elf":
        if name is None or name.endswith((".c", ".h")):
            return files_lines(path, name, say=say)

        lines = source_lines(path, name, say=say)

        if asm:
            lines += ["", "Disassembly:", *function_lines(path, name)]

        return lines

    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return [f"Unable to read {path}"]

    if name is None:
        return _numbered(text)

    if kind == "shell":
        line = shell_function_lines(path).get(name)
    elif kind == "perl":
        line = dict(scan_perl(path).subs).get(name)
    else:
        line = None

    if line is None:
        return [f"No function named {name[:60]} in this script"]

    return _numbered(text[line - 1:], start=line, limit=60)
