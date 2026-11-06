"""XRAY capability contracts: what one program may do, in a reviewable text file.

The format is specified in docs/contract-spec.md. In short:

    xray-contract 1
    program /usr/bin/tool
    sha256 4f2c...
    package tool 1.2-1

    [exec]
    /usr/bin/grep        # inferred: /usr/bin/tool:12 runs `grep`
    [load]
    /usr/lib/libc.so.6   # declared: DT_NEEDED libc.so.6
    [read]
    /etc/tool.conf       # observed
    ~/.config/tool/**
    [write]
    ~/.cache/tool/*
    [net]
    none

A path entry is an absolute path or one starting with "~/" (the home
directory of whoever runs the program). "*" in the last component
matches one name; a trailing "/**" matches everything beneath a
directory. Text after "#" is a comment: the generator puts the evidence
for each entry there. "write" implies "read", and "exec" implies "read".
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

CONTRACT_VERSION = 1
SECTIONS = ("exec", "load", "read", "write", "net")
HEADER_KEYS = ("program", "sha256", "package", "generated", "workload")

# What every contract allows without listing it: the loader cache, locale
# data and the kernel's pseudo files. Spec section "Baseline".
BASELINE_READ = (
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/etc/localtime",
    "/usr/lib/locale/**",
    "/usr/lib64/locale/**",
    "/usr/share/locale/**",
    "/usr/share/zoneinfo/**",
    "/usr/lib/gconv/**",
    "/usr/lib64/gconv/**",
    "/proc/**",
    "/sys/**",
)
BASELINE_DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/pts/**")

_NET = re.compile(r"^(none|any|unix|(connect|bind) (tcp|udp) (\*|\d{1,5}))$")


class ContractError(ValueError):
    """A contract file that does not follow the format."""


@dataclass(frozen=True)
class Entry:
    value: str
    comment: str = ""

    def basis(self):
        word = self.comment.split(":", 1)[0].strip()
        return word if word in ("observed", "declared", "inferred", "guessed", "baseline", "required") else None


@dataclass
class Contract:
    program: str
    sha256: str | None = None
    package: str | None = None
    generated: str | None = None
    workload: str | None = None
    sections: dict = field(default_factory=lambda: {name: [] for name in SECTIONS})
    notes: list = field(default_factory=list)

    # -- editing -----------------------------------------------------------
    def add(self, section, value, comment=""):
        if section not in SECTIONS:
            raise ContractError(f"unknown section [{section}]")
        if section == "net":
            _check_net(value)
        else:
            _check_path(value)
        entries = self.sections[section]
        for index, entry in enumerate(entries):
            if entry.value == value:
                if not entry.comment and comment:
                    entries[index] = Entry(value, comment)
                return
        entries.append(Entry(value, comment))

    def remove(self, section, value):
        self.sections[section] = [entry for entry in self.sections[section] if entry.value != value]

    def values(self, section):
        return [entry.value for entry in self.sections[section]]

    # -- questions -----------------------------------------------------------
    def allows(self, section, path, home=None):
        """True when the contract (or the baseline) allows this access to path."""

        path = os.path.normpath(path)
        if section in ("read", "exec", "load") and _any_match(BASELINE_READ + BASELINE_DEVICES, path, home):
            return True
        if section == "write" and _any_match(BASELINE_DEVICES, path, home):
            return True
        granted = {
            "exec": ("exec",),
            "load": ("load", "exec", "read", "write"),
            "read": ("read", "write", "exec", "load"),
            "write": ("write",),
        }[section]
        return any(_any_match(self.values(name), path, home) for name in granted)

    def net_allows(self, kind, protocol=None, port=None):
        """kind is "connect", "bind" or "unix"."""

        values = self.values("net")
        if "any" in values:
            return True
        if kind == "unix":
            return "unix" in values
        for value in values:
            parts = value.split()
            if len(parts) == 3 and parts[0] == kind and parts[1] == protocol and parts[2] in ("*", str(port)):
                return True
        return False

    # -- text ------------------------------------------------------------------
    def render(self):
        lines = ["# XRAY capability contract (docs/contract-spec.md)", f"xray-contract {CONTRACT_VERSION}"]
        for key in HEADER_KEYS:
            value = getattr(self, key)
            if value:
                lines.append(f"{key} {value}")
        for note in self.notes:
            lines.append(f"# {note}")
        for name in SECTIONS:
            lines.append("")
            lines.append(f"[{name}]")
            entries = self.sections[name]
            if name == "net" and not entries:
                entries = [Entry("none")]
            width = min(60, max((len(entry.value) for entry in entries), default=0))
            for entry in entries:
                text = entry.value
                if entry.comment:
                    text = f"{text:<{width}}  # {entry.comment}"
                lines.append(text)
        return "\n".join(lines) + "\n"


def _check_path(value):
    if not (value.startswith(("/", "~/"))):
        raise ContractError(f"path entries must be absolute or start with ~/: {value}")
    if "**" in value and not value.endswith("/**"):
        raise ContractError(f"** is only allowed as a final /** component: {value}")


def _check_net(value):
    if not _NET.match(value):
        raise ContractError(f"bad [net] entry: {value} (none, any, unix, connect|bind tcp|udp PORT|*)")


def expand_home(value, home=None):
    if value.startswith("~/"):
        return str(Path(home or os.path.expanduser("~")) / value[2:])
    return value


def matches(pattern, path, home=None):
    """True when a contract path entry covers path."""

    pattern = expand_home(pattern, home)
    if pattern.endswith("/**"):
        base = pattern[:-3]
        return path == base or path.startswith(base.rstrip("/") + "/")
    if any(ch in pattern for ch in "*?["):
        return Path(path).parent == Path(pattern).parent and fnmatch.fnmatchcase(Path(path).name, Path(pattern).name)
    return path == pattern


def _any_match(patterns, path, home):
    return any(matches(pattern, path, home) for pattern in patterns)


def parse_contract(text):
    """Parse contract text; raise ContractError on anything not in the format."""

    contract = None
    section = None
    for number, raw in enumerate(text.splitlines(), 1):
        line, _, comment = raw.partition("#")
        line, comment = line.strip(), comment.strip()
        if not line:
            continue
        try:
            if contract is None:
                if line != f"xray-contract {CONTRACT_VERSION}":
                    raise ContractError(f"expected 'xray-contract {CONTRACT_VERSION}' first, got: {line}")
                contract = Contract(program="")
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                if section not in SECTIONS:
                    raise ContractError(f"unknown section [{section}]")
                continue
            if section is None:
                key, _, value = line.partition(" ")
                if key not in HEADER_KEYS or not value.strip():
                    raise ContractError(f"unknown header line: {line}")
                setattr(contract, key, value.strip())
                continue
            if section == "net" and line == "none":
                continue
            contract.add(section, line, comment)
        except ContractError as error:
            raise ContractError(f"line {number}: {error}") from None
    if contract is None:
        raise ContractError("empty contract")
    if not contract.program:
        raise ContractError("missing 'program' line")
    return contract


def load_contract(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise ContractError(f"cannot read {path}: {error.strerror}") from None
    return parse_contract(text)
