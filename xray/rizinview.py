import difflib
import re
import subprocess
from pathlib import Path

from xray.entrypoints import command_kind
from xray.minidebug import read_function_table

INSTALL_HINT = "rizin not found: install it with: sudo dnf install rizin"


def function_lines(path, name, timeout=30, max_lines=200):
    """Return rizin's annotated disassembly of one function.

    The name is looked up in the function table of .gnu_debugdata and
    rizin is given the address, never the name, so an unknown or odd
    name cannot reach it. The binary is read, never run.
    """

    path = Path(path)

    if command_kind(path) != "elf":
        return ["Not an ELF binary: --disasm-function reads ELF only"]

    table = read_function_table(path)

    if not table:
        return ["No function names in this binary (it has no .gnu_debugdata)"]

    found = [entry for entry in table if entry[2] == name]

    if not found:
        close = difflib.get_close_matches(
            name, [entry[2] for entry in table], n=5, cutoff=0.6
        )
        shown = re.sub(r"[^\x20-\x7e]", "?", name)[:60]
        lines = [f"Unknown function: {shown}"]

        if close:
            lines.append("Did you mean:")
            lines.extend(f"- {item}" for item in close)

        return lines

    address = found[0][0]

    try:
        result = subprocess.run(
            ["rizin", "-q", "-c", f"aa; s 0x{address:x}; af; pdf", str(path)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return [INSTALL_HINT]
    except subprocess.TimeoutExpired:
        return [f"rizin took longer than {timeout} seconds: stopped"]
    except OSError as error:
        return [f"Unable to run rizin: {error}"]

    lines = result.stdout.rstrip("\n").splitlines()

    if not lines:
        return ["rizin printed nothing for this function"]

    if len(lines) > max_lines:
        hidden = len(lines) - max_lines
        lines = lines[:max_lines] + [f"... and {hidden} more lines"]

    return lines
