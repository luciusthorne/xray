"""Explain a capability down to the source: which functions call an imported symbol, and on which line.

For each requested symbol (``system``, ``connect``, ``dlopen``...), the
binary is disassembled with objdump and every call to it is found: direct
calls through the PLT, tail-call jumps, and indirect calls through the GOT
that objdump annotates (``-fno-plt`` builds). Each call address is then
mapped to its function and source line with eu-addr2line (or addr2line),
using the binary's own debug information or, when it was stripped, the
debug file a configured debuginfod server holds for its build ID. Nothing
is run.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

_CALL = re.compile(r"^\s*([0-9a-f]+):\s+(call|jmp)\w*\s+.*?<([^@>+]+)(?:@[^>]*)?(?:\+0x[0-9a-f]+)?>\s*$")


@dataclass
class CallSite:
    symbol: str
    address: int
    instruction: str
    function: str | None = None
    location: str | None = None  # file:line
    inlined: list = field(default_factory=list)  # [(function, file:line)] from inner to outer


def _objdump(path):
    try:
        done = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-w", str(path)], capture_output=True,
                              text=True, errors="replace", check=False, timeout=300,
                              env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout


def call_sites(path, symbols):
    """[CallSite] for every call or tail call to one of symbols in the binary."""

    wanted = set(symbols)
    sites = []
    section = ""
    for line in _objdump(path).splitlines():
        if line.startswith("Disassembly of section "):
            section = line.split()[-1].rstrip(":")
            continue
        if section.startswith(".plt"):
            continue  # the stubs themselves, not callers
        match = _CALL.match(line)
        if not match:
            continue
        address, kind, target = match.groups()
        if target in wanted:  # call <system@plt>, jmp <system@plt>, or call *... # <system@GLIBC_2.2.5>
            sites.append(CallSite(target, int(address, 16), kind))
    return sites


def debug_file(path):
    """The file to read line information from: the binary itself, or its debuginfod debug file."""

    try:
        sections = subprocess.run(["readelf", "-S", "-W", str(path)], capture_output=True, text=True,
                                  errors="replace", check=False, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        sections = ""
    if ".debug_line" in sections or ".debug_info" in sections:
        return str(path), "the binary's own debug information"
    from . import debuginfod

    if not debuginfod.configured():
        return None, "stripped, and no debuginfod server is configured (DEBUGINFOD_URLS)"
    lib = debuginfod._library()
    build_id = debuginfod._build_id(path)
    if lib is None or build_id is None:
        return None, "stripped, and libdebuginfod or a build ID is missing"
    client = debuginfod._begin(lib)
    if not client:
        return None, "could not start a debuginfod client"
    try:
        found = debuginfod._lookup(lib, client, build_id)
    finally:
        lib.debuginfod_end(client)
    if found is None:
        return None, f"no debug information for build ID {build_id} on the configured debuginfod servers"
    return str(found), f"debuginfod (build ID {build_id})"


def locate(sites, debug_path):
    """Fill in function and file:line for each call site from debug_path."""

    if not sites or debug_path is None:
        return sites
    tool = shutil.which("eu-addr2line")
    addresses = [hex(site.address) for site in sites]
    if tool:
        command = [tool, "-f", "-i", "-e", debug_path, *addresses]
    elif shutil.which("addr2line"):
        command = ["addr2line", "-f", "-i", "-C", "-e", debug_path, *addresses]
    else:
        return sites
    try:
        output = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False,
                                timeout=120).stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return sites
    # Without a separator between addresses, inline chains are read by re-running one address at a time
    # when -i produced more lines than two per address.
    if len(output) == 2 * len(sites):
        for index, site in enumerate(sites):
            _fill(site, output[2 * index], output[2 * index + 1])
        return sites
    for site in sites:
        try:
            lines = subprocess.run([*command[:-len(addresses)], hex(site.address)], capture_output=True, text=True,
                                   errors="replace", check=False, timeout=60).stdout.splitlines()
        except (OSError, subprocess.TimeoutExpired):
            continue
        pairs = [(lines[i], lines[i + 1]) for i in range(0, len(lines) - 1, 2)]
        if pairs:
            _fill(site, *pairs[0])
            site.inlined = [(name.split(" ")[0], _clean(where)) for name, where in pairs[1:]]
    return sites


def _clean(where):
    where = where.strip()
    return None if where.startswith("??") else re.sub(r"\s*\(discriminator \d+\)", "", where)


def _fill(site, function, where):
    site.function = None if function.startswith("??") else function.strip().split(" ")[0]
    site.location = _clean(where)


def explain(path, symbols):
    """Return (sites, how): every call to symbols in path, with function and source line where known."""

    sites = call_sites(path, symbols)
    target, how = debug_file(path) if sites else (None, "no call sites found")
    return locate(sites, target), how


def explain_lines(path, symbols, sites, how):
    lines = [f"Calls to {', '.join(symbols)} in {path}", f"Line information: {how}", ""]
    if not sites:
        lines.append("No direct calls found. The symbol may be reached through a function pointer or dlsym,")
        lines.append("which a call-site search cannot see.")
        return lines
    for site in sites:
        where = site.location or "source line unknown"
        function = site.function or "unknown function"
        lines.append(f"  {site.symbol:<10} {site.instruction:<4} at 0x{site.address:x}  in {function}  ({where})")
        for name, inner in site.inlined:
            lines.append(f"  {'':<10}      inlined into {name} ({inner or 'unknown'})")
    return lines
