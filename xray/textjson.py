"""Structured JSON for any text query, behind a trailing --json.

Text queries share one layout: a title over a rule, headings over rules,
"Key: value" fields, and "- item" lists. This module reads that layout
back into data, so every query gains machine-readable output through one
code path instead of one exporter per option.
"""

import re

SCHEMA_VERSION = 1

_RULE = re.compile(r"^[─═]{3,}$")
_FIELD = re.compile(r"^([A-Z][A-Za-z0-9 ()/_.'-]{0,48}):(?:\s+(.*))?$")


def _section(heading):
    return {"heading": heading, "fields": {}, "items": [], "lines": []}


def text_to_data(lines, query, target):
    """Return the JSON document for the lines a text query printed."""

    lines = [line.rstrip() for line in lines]

    if len(lines) >= 2 and lines[0] == "XRAY" and _RULE.match(lines[1]):
        lines = lines[2:]

    title = None
    sections = []
    current = _section(None)
    open_field = None
    index = 0

    while index < len(lines):
        line = lines[index]
        following = lines[index + 1] if index + 1 < len(lines) else ""

        if not line.strip():
            index += 1
            continue

        if not line.startswith(" ") and _RULE.match(following.strip()):
            if title is None and not sections and current == _section(None):
                title = line.strip()
            else:
                if current != _section(current["heading"]):
                    sections.append(current)
                current = _section(line.strip())
            open_field = None
            index += 2
            continue

        stripped = line.strip()

        if stripped.startswith("- "):
            item = stripped[2:]
            if open_field is not None:
                current["fields"][open_field].append(item)
            else:
                current["items"].append(item)
            index += 1
            continue

        match = _FIELD.match(line)

        if match:
            key, value = match.group(1), match.group(2)
            if value is None or value == "":
                current["fields"][key] = []
                open_field = key
            else:
                current["fields"][key] = value
                open_field = None
            index += 1
            continue

        open_field = None
        current["lines"].append(line)
        index += 1

    if current != _section(current["heading"]) or not sections:
        sections.append(current)

    return {
        "schema_version": SCHEMA_VERSION,
        "query": query,
        "target": str(target),
        "title": title,
        "sections": sections,
    }
