import bisect
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from xray.entrypoints import command_kind
from xray.minidebug import read_function_table

_SITE = re.compile(r"^\s*([0-9a-fA-F]+):\s")
_CALL = re.compile(r"\bcall\s+(?:([0-9a-fA-F]+)\s+<([^>]*)>|(\*.*?))\s*$")
_ASM_LABEL = re.compile(r"^\s*[0-9a-fA-F]+\s+<(.+)>:$")
_ASM_SECTION = re.compile(r"^Disassembly of section .+:")


def _matches_symbol(label, name):
    """Match an exact symbol or its ELF version suffix, not a nearby offset."""
    return bool(
        label == name
        or re.fullmatch(re.escape(name) + r"@{1,2}[A-Za-z0-9_.]+", label)
    )


def assembly_lines(path, name=None, max_lines=400, timeout=30):
    """Read machine instructions with objdump when source is unavailable."""
    path = Path(path)
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    command = ["objdump", "-d", "-C"]
    if name is not None:
        symbol = next(
            (
                entry
                for entry in read_function_table(path)
                if _matches_symbol(entry[2], name)
            ),
            None,
        )
        if symbol is not None and symbol[1] > 0:
            command.extend(
                [f"--start-address={symbol[0]}", f"--stop-address={symbol[0] + symbol[1]}"]
            )
    command.append(str(path))
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return ["objdump not found: install binutils to read machine code"]
    except subprocess.TimeoutExpired:
        return [f"objdump took longer than {timeout} seconds: stopped"]
    except OSError as error:
        return [f"Unable to run objdump: {error}"]

    if result.returncode != 0 or not result.stdout.strip():
        message = result.stderr.strip() or "objdump returned no disassembly"
        return [f"Unable to disassemble {path}: {message}"]

    lines = result.stdout.splitlines()
    if name is not None:
        starts = [
            index for index, line in enumerate(lines)
            if (match := _ASM_LABEL.match(line))
            and _matches_symbol(match.group(1), name)
        ]
        if not starts:
            labels = [
                match.group(1) for line in lines
                if (match := _ASM_LABEL.match(line))
            ]
            return [
                f"No disassembly label named {name[:60]} was found",
                "Available labels: " + (", ".join(labels[:20]) or "none"),
            ]
        start = starts[0]
        end = next(
            (
                index for index in range(start + 1, len(lines))
                if _ASM_LABEL.match(lines[index]) or _ASM_SECTION.match(lines[index])
            ),
            len(lines),
        )
        lines = lines[start:end]

    shown = lines[:max_lines]
    if len(lines) > max_lines:
        shown.append(f"... and {len(lines) - max_lines} more lines")
    return shown


@dataclass(frozen=True)
class DisasmResult:
    """Direct calls found by reading disassembly.

    calls maps a function to the sorted, unique callee names it calls
    directly. Names ending in @plt are imports. The counters hold
    calls that cannot be resolved: indirect (through a register or
    memory), offset (into the middle of a function), unresolved (to an
    address no function covers) and unattributed (no function names
    were available to say which function the call is in).
    """

    calls: dict = field(default_factory=dict)
    indirect: int = 0
    offset: int = 0
    unresolved: int = 0
    unattributed: int = 0


class _Spans:
    def __init__(self, table):
        ordered = sorted(table)
        self.starts = []
        self.spans = []

        for index, (address, size, name) in enumerate(ordered):
            end = address + size

            if size == 0:
                end = ordered[index + 1][0] if index + 1 < len(ordered) else address

            self.starts.append(address)
            self.spans.append((address, end, name))

    def find(self, address):
        index = bisect.bisect_right(self.starts, address) - 1

        if index < 0:
            return None

        start, end, name = self.spans[index]

        return (start, name) if address < end else None


def parse_calls(text, table=()):
    """Return a DisasmResult from objdump -d output and a function table.

    table holds (address, size, name) of known functions. Call sites
    and call targets are matched against it by address, because the
    names objdump prints for stripped code (name+0x...) are only the
    nearest exported symbol. Without a table nothing can be attributed.
    """

    spans = _Spans(table)
    calls = {}
    indirect = offset = unresolved = unattributed = 0

    for line in text.splitlines():
        match = _CALL.search(line)

        if not match:
            continue

        if match.group(3) is not None:
            indirect += 1
            continue

        site = _SITE.match(line)
        caller = spans.find(int(site.group(1), 16)) if site else None

        if caller is None:
            unattributed += 1
            continue

        label = match.group(2)

        if label.endswith("@plt") and "+" not in label:
            calls.setdefault(caller[1], set()).add(label)
            continue

        target_address = int(match.group(1), 16)
        target = spans.find(target_address)

        if target is None:
            unresolved += 1
        elif target[0] != target_address:
            offset += 1
        else:
            calls.setdefault(caller[1], set()).add(target[1])

    return DisasmResult(
        {name: tuple(sorted(found)) for name, found in calls.items()},
        indirect,
        offset,
        unresolved,
        unattributed,
    )


def disasm_lines(path, timeout=30, max_callers=40, max_callees=10):
    """Return report lines for the direct calls inside an ELF binary.

    This reads objdump -d and never runs the program. Function names
    come from .gnu_debugdata when the binary has it. Indirect calls
    and calls that cannot be matched to a function are counted, not
    guessed.
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

    parsed = parse_calls(result.stdout, read_function_table(path))

    if not (
        parsed.calls
        or parsed.indirect
        or parsed.offset
        or parsed.unresolved
        or parsed.unattributed
    ):
        return ["No calls found (is this a stripped or empty binary?)"]

    lines = [
        f"Functions that call others: {len(parsed.calls)}",
        f"Indirect calls (not resolved): {parsed.indirect}",
        f"Calls into the middle of a function (not resolved): {parsed.offset}",
    ]

    if parsed.unresolved:
        lines.append(
            f"Calls to unknown addresses (not resolved): {parsed.unresolved}"
        )

    if parsed.unattributed:
        lines.append(
            "Calls not attributed to a function (no function names "
            f"in this binary): {parsed.unattributed}"
        )

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


def disasm_result(path, timeout=30):
    """Return the DisasmResult for an ELF binary, or None.

    None when the file is not ELF, objdump is missing or too slow, or
    anything fails. The binary is only read, never run.
    """

    path = Path(path)

    if command_kind(path) != "elf":
        return None

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
    except (OSError, subprocess.SubprocessError):
        return None

    return parse_calls(result.stdout, read_function_table(path))
