"""Policy as code: rules over XRAY findings, first match wins.

A policy is a text file, one rule per line, ``#`` comments::

    # never accept a loader hook or a new setuid bit, from any package
    deny gain loader-hook
    deny gain setuid
    # ghostty may use the network; nothing else in /usr/bin may start to
    allow gain class:net for ghostty
    deny gain class:net in usr/bin/*
    # libraries must not start running shells
    deny gain class:shell in *.so*
    # untrusted input must never reach code
    deny taint high
    # everything "Worth a look" in a scan is a violation
    deny risk *

A rule is ``allow|deny KIND [PATTERN] [in PATH-GLOB] [for PACKAGE-GLOB]``.
KIND is ``gain`` (drift, feed and hook results; PATTERN matches the gain's
field, such as ``class:net``, ``loader-hook``, ``needed``, ``runpath``),
``taint`` (PATTERN is a severity: high, medium, low), ``risk`` (PATTERN
matches the message) or ``breach`` (contract check breaches; PATTERN
matches the section). Patterns and globs use shell wildcards; a missing
PATTERN matches everything. Rules are tried in order and the first that
matches decides; items no rule matches are allowed.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

KINDS = ("gain", "taint", "risk", "breach")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    action: str
    kind: str
    pattern: str = "*"
    path: str = "*"
    package: str = "*"
    line: int = 0
    text: str = ""

    def matches(self, item):
        if item["kind"] != self.kind:
            return False
        if not fnmatch.fnmatchcase(item.get("key") or "", self.pattern):
            return False
        path = (item.get("path") or "").lstrip("/")
        if self.path != "*" and not (fnmatch.fnmatchcase(path, self.path.lstrip("/"))
                                     or fnmatch.fnmatchcase(Path(path).name, self.path)):
            return False
        return fnmatch.fnmatchcase(item.get("package") or "", self.package)


def parse(text):
    rules = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split()
        if words[0] not in ("allow", "deny") or len(words) < 2 or words[1] not in KINDS:
            raise PolicyError(f"line {number}: expected 'allow|deny {'|'.join(KINDS)} ...': {raw.strip()}")
        action, kind, rest = words[0], words[1], words[2:]
        pattern = "*"
        if rest and rest[0] not in ("in", "for"):
            pattern = rest.pop(0)
        fields = {"path": "*", "package": "*"}
        while rest:
            if len(rest) < 2 or rest[0] not in ("in", "for"):
                raise PolicyError(f"line {number}: expected 'in PATH-GLOB' or 'for PACKAGE-GLOB': {raw.strip()}")
            fields["path" if rest[0] == "in" else "package"] = rest[1]
            rest = rest[2:]
        if kind == "taint" and pattern not in ("*", "high", "medium", "low", "info"):
            raise PolicyError(f"line {number}: taint takes a severity (high, medium, low, info): {pattern}")
        rules.append(Rule(action, kind, pattern, fields["path"], fields["package"], number, raw.strip()))
    return rules


def load(path):
    try:
        return parse(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise PolicyError(f"cannot read {path}: {error.strerror}") from None


def decide(rules, item):
    for rule in rules:
        if rule.matches(item):
            return rule
    return None


def violations(rules, items):
    """[(item, rule)] for every item whose first matching rule denies it."""

    out = []
    for item in items:
        rule = decide(rules, item)
        if rule is not None and rule.action == "deny":
            out.append((item, rule))
    return out


# -- turning XRAY results into policy items --------------------------------------------

def gain_items(gains, package=None):
    return [{"kind": "gain", "key": gain["field"], "path": gain.get("path"), "package": package,
             "detail": gain["detail"]} for gain in gains]


def taint_items(findings):
    return [{"kind": "taint", "key": item["severity"], "path": item["file"], "package": None,
             "detail": f"{item['detail']} ({item['file']}:{item.get('line') or '-'})"} for item in findings]


def risk_items(risks):
    return [{"kind": "risk", "key": entry["message"], "path": entry["file"], "package": None,
             "detail": entry["message"]} for entry in risks]


def breach_items(breaches):
    return [{"kind": "breach", "key": item["section"], "path": item["value"], "package": None,
             "detail": f"{item['section']} {item['value']}: {item['detail']}"} for item in breaches]


def violation_lines(found):
    if not found:
        return ["Policy: no violations."]
    lines = [f"Policy: {len(found)} violation(s)"]
    for item, rule in found:
        where = f"{item['package']} " if item.get("package") else ""
        lines.append(f"  {where}{item.get('path') or ''}: {item['detail'][:140]}")
        lines.append(f"      denied by line {rule.line}: {rule.text}")
    return lines
