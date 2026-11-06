"""Taint leads inside compiled programs, from the order of calls in machine code.

A compiled program is disassembled with objdump and split into functions
(from its symbol table, or from the debug file a debuginfod server holds
when it was stripped). A lead is a function that calls an input function
(getenv, fgets, read, recv, ...) and then, later in the same function or
through the functions it calls (up to a few levels), a code-execution
function (system, popen, exec*, dlopen). Each lead names both call sites
with their source lines when debug information is available.

This follows call order, not data: it cannot tell whether the input value
is what reaches the sink. Every lead is therefore labelled "guessed" and is
something to read, not a finding.
"""

from __future__ import annotations

import os
import re
import subprocess
from bisect import bisect_right
from dataclasses import dataclass, field

from .explain import CallSite, debug_file, locate
from .minidebug import parse_function_table

SOURCES = {
    "getenv": "env", "secure_getenv": "env",
    "fgets": "input", "getline": "input", "getdelim": "input", "fread": "input", "read": "input",
    "scanf": "input", "fscanf": "input", "__isoc99_scanf": "input", "__isoc99_fscanf": "input",
    "recv": "network", "recvfrom": "network", "recvmsg": "network",
}
SINKS = ("system", "popen", "execv", "execvp", "execve", "execl", "execlp", "execle", "execvpe", "fexecve",
         "posix_spawn", "posix_spawnp", "dlopen")
_CALL = re.compile(r"^\s*([0-9a-f]+):\s+(?:call|jmp)\w*\s+(?:[0-9a-f]+\s+)?.*?<([^@>+]+)(@[^>]*)?(\+0x[0-9a-f]+)?>")


@dataclass
class Lead:
    function: str
    source: CallSite
    sink: CallSite
    via: list = field(default_factory=list)  # internal functions between the source's function and the sink
    kind: str = "input"


def _symbols(path):
    try:
        text = subprocess.run(["readelf", "-sW", str(path)], capture_output=True, text=True, errors="replace",
                              check=False, timeout=60, env={**os.environ, "LC_ALL": "C"}).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ()
    return parse_function_table(text)


def function_table(path):
    """[(address, size, name)] of defined functions, from the binary or its debug file."""

    table = _symbols(path)
    if len([entry for entry in table if entry[1]]) > 5:
        return table, None
    debug, _how = debug_file(path)
    if debug and debug != str(path):
        return _symbols(debug), debug
    return table, debug


def calls_by_function(path, table):
    """{function: [(address, callee name, imported?)]} in address order."""

    starts = [address for address, _, _ in table]
    names = {address: name for address, _, name in table}
    sizes = {address: size for address, size, _ in table}
    out = {}
    try:
        text = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-w", str(path)], capture_output=True,
                              text=True, errors="replace", check=False, timeout=600,
                              env={**os.environ, "LC_ALL": "C"}).stdout
    except (OSError, subprocess.TimeoutExpired):
        return out
    section = ""
    for line in text.splitlines():
        if line.startswith("Disassembly of section "):
            section = line.split()[-1].rstrip(":")
            continue
        if section.startswith(".plt"):
            continue
        match = _CALL.match(line)
        if not match:
            continue
        if match.group(4):
            continue  # a jump to an offset inside a function is a branch, not a call
        address = int(match.group(1), 16)
        index = bisect_right(starts, address) - 1
        if index < 0:
            continue
        start = starts[index]
        if sizes[start] and address >= start + sizes[start]:
            continue
        imported = bool(match.group(3))
        out.setdefault(names[start], []).append((address, match.group(2), imported))
    return out


def leads(path, depth=3, limit=50):
    """Return ([Lead], how): input calls followed by code-execution calls."""

    table, debug = function_table(path)
    if not table:
        return [], "no function table (stripped, and no debug information found)"
    calls = calls_by_function(path, table)

    reach = {}

    def sinks_from(function, level, seen):
        """[(sink CallSite, via path)] reachable from a function within level calls."""

        key = (function, level)
        if key in reach:
            return reach[key]
        found = []
        for address, callee, imported in calls.get(function, ()):
            if callee in SINKS:
                found.append((CallSite(callee, address, "call"), []))
            elif level > 0 and callee in calls and callee not in seen:
                for site, via in sinks_from(callee, level - 1, seen | {callee}):
                    found.append((site, [callee, *via]))
        reach[key] = found
        return found

    out = []
    for function, sequence in calls.items():
        for position, (address, callee, _imported) in enumerate(sequence):
            if callee not in SOURCES:
                continue
            for later_address, later, _ in sequence[position + 1:]:
                candidates = []
                if later in SINKS:
                    candidates = [(CallSite(later, later_address, "call"), [])]
                elif later in calls and depth > 0:
                    candidates = [(site, [later, *via]) for site, via in sinks_from(later, depth - 1, {function, later})]
                for site, via in candidates:
                    out.append(Lead(function, CallSite(callee, address, "call"), site, via, SOURCES[callee]))
            if len(out) >= limit:
                break
    unique = {}
    for lead in out:
        unique.setdefault((lead.function, lead.source.address, lead.sink.address), lead)
    out = sorted(unique.values(), key=lambda lead: ({"network": 0, "input": 1, "env": 2}[lead.kind], lead.function))
    out = out[:limit]
    sites = [lead.source for lead in out] + [lead.sink for lead in out]
    locate(sites, debug if debug else str(path))
    how = "symbols and line information from the binary" if debug in (None, str(path)) else "debuginfod debug file"
    return out, how


def lead_lines(path, found, how):
    lines = [f"Taint leads in {path} (guessed: call order in machine code, no data flow)", f"Symbols: {how}", ""]
    if not found:
        lines.append("No function calls an input function and then a code-execution function.")
        return lines
    for lead in found:
        via = f" via {' -> '.join(lead.via)}" if lead.via else ""
        lines.append(f"[{lead.kind}] {lead.function}: {lead.source.symbol}() then {lead.sink.symbol}(){via}")
        lines.append(f"    input at {lead.source.location or hex(lead.source.address)}")
        lines.append(f"    sink  at {lead.sink.location or hex(lead.sink.address)}")
    return lines
