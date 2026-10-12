import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from xray.entrypoints import command_kind

_HEADER = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:\s*$")
_CALL = re.compile(r"\bcall\s+(?:[0-9a-fA-F]+\s+<([^>]+)>|(\*.*))\s*$")


@dataclass(frozen=True)
class DisasmResult:
    """Direct calls found by reading disassembly.

    calls maps a function to the sorted, unique callee names it calls
    directly. Names ending in @plt are imports. indirect counts calls
    through a register or memory, and offset counts calls into the
    middle of a function (name+0x..). Neither can be resolved.
    """

    calls: dict = field(default_factory=dict)
    indirect: int = 0
    offset: int = 0


def parse_calls(text):
    """Return a DisasmResult from objdump -d output.

    The .init and .plt sections and the @plt stubs hold no calls
    worth listing, so they are not reported as callers.
    """

    calls = {}
    current = None
    indirect = 0
    offset = 0

    for line in text.splitlines():
        header = _HEADER.match(line)

        if header:
            name = header.group(1)
            current = None if name.startswith(".") or name.endswith("@plt") else name
            continue

        match = _CALL.search(line)

        if not match:
            continue

        if match.group(2) is not None:
            indirect += 1
        elif "+0x" in match.group(1):
            offset += 1
        elif current is not None:
            calls.setdefault(current, set()).add(match.group(1))

    return DisasmResult(
        {name: tuple(sorted(found)) for name, found in calls.items()},
        indirect,
        offset,
    )


def disasm_lines(path, timeout=30, max_callers=40, max_callees=10):
    """Return report lines for the direct calls inside an ELF binary.

    This reads objdump -d. It never runs the program. Indirect calls
    and calls into the middle of a function are counted, not resolved.
    """

    path = Path(path)

    if command_kind(path) != "elf":
        return ["Not an ELF binary: --disasm reads ELF only"]

    env = dict(os.environ)
    env["LC_ALL"] = "C"

    try:
        result = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", str(path)],
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return ["objdump not found: install binutils to read calls"]
    except subprocess.TimeoutExpired:
        return [f"objdump took longer than {timeout} seconds: stopped"]
    except OSError as error:
        return [f"Unable to run objdump: {error}"]

    parsed = parse_calls(result.stdout)

    if not parsed.calls and not parsed.indirect and not parsed.offset:
        return ["No calls found (is this a stripped or empty binary?)"]

    lines = [
        f"Functions that call others: {len(parsed.calls)}",
        f"Indirect calls (not resolved): {parsed.indirect}",
        f"Calls into the middle of a function (not resolved): {parsed.offset}",
    ]
    names = sorted(parsed.calls)

    for caller in names[:max_callers]:
        lines.append(caller)
        callees = parsed.calls[caller]

        for callee in callees[:max_callees]:
            if callee.endswith("@plt"):
                lines.append(f"  -> {callee[:-4]} (import)")
            else:
                lines.append(f"  -> {callee}")

        if len(callees) > max_callees:
            lines.append(f"  ... and {len(callees) - max_callees} more")

    if len(names) > max_callers:
        lines.append(f"... and {len(names) - max_callers} more functions")

    return lines
