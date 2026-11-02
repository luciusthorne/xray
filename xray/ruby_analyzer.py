"""Ruby source reader backed by Ruby's standard-library Ripper parser.

The target source is parsed as input to Ripper; it is never executed.
Only literal require/require_relative calls are followed.
"""

import json
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from .analysis_cache import get_or_compute
from .analyzers import Analyzer, registry
from .errors import AnalysisError, FileError
from .model import Edge
from .symbols import Symbol

_RIPPER = r"""
require 'ripper'
require 'json'
source = STDIN.read
tree = Ripper.sexp(source)
tokens = Ripper.lex(source).map do |position, event, text, _state|
  [event.to_s, text, position[0]]
end
STDOUT.write(JSON.generate({'valid' => !tree.nil?, 'tokens' => tokens, 'tree' => tree}))
"""

_IGNORED = {"on_sp", "on_ignored_nl", "on_nl", "on_comment"}


def _parse(path):
    path = Path(path).resolve()

    try:
        stat = path.stat()
    except OSError as error:
        raise FileError(f"Unable to read file: {path}") from error

    return _parse_snapshot(
        str(path), stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size
    )


@lru_cache(maxsize=128)
def _parse_snapshot(path_text, _mtime_ns, _ctime_ns, _size):
    path = Path(path_text)

    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise FileError(f"Unable to read file: {path}") from error
    except UnicodeError as error:
        raise FileError(f"Unable to decode file: {path}") from error

    ruby = shutil.which("ruby")

    if ruby is None:
        raise AnalysisError("Ruby analysis requires the ruby interpreter")

    try:
        version = subprocess.run(
            [ruby, "--version"], capture_output=True, text=True,
            timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AnalysisError(f"Unable to identify Ruby parser version: {error}") from error

    if version.returncode != 0:
        raise AnalysisError("Unable to identify Ruby parser version")

    def compute():
        try:
            result = subprocess.run(
                [ruby, "-e", _RIPPER],
                input=source,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AnalysisError(f"Ruby parser failed for {path}: {error}") from error

        if result.returncode != 0:
            raise AnalysisError(f"Ruby parser failed for {path}: {result.stderr.strip()}")

        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise AnalysisError(f"Ruby parser returned invalid data for {path}") from error

        if not parsed["valid"]:
            raise AnalysisError(f"Invalid Ruby syntax: {path}")

        return {
            "symbols": [
                {
                    "name": symbol.name,
                    "kind": symbol.kind,
                    "line": symbol.line,
                    "parent": symbol.parent,
                    "metadata": dict(symbol.metadata),
                }
                for symbol in _symbols(path, parsed["tokens"], parsed["tree"])
            ],
            "requires": [
                {"kind": kind, "name": name, "line": line}
                for kind, name, line in _require_calls(parsed["tokens"])
            ],
        }

    data = get_or_compute(
        "ruby", version.stdout.strip() + ":ripper-v4", source.encode("utf-8"), compute
    )
    return path, data


def _significant(tokens, index):
    while index < len(tokens) and tokens[index][0] in _IGNORED:
        index += 1

    return index


def _literal_string(tokens, index):
    index = _significant(tokens, index)

    if index < len(tokens) and tokens[index][1] == "(":
        index = _significant(tokens, index + 1)

    if index >= len(tokens) or tokens[index][0] != "on_tstring_beg":
        return None

    index += 1
    pieces = []

    while index < len(tokens) and tokens[index][0] != "on_tstring_end":
        event, text, _line = tokens[index]

        if event != "on_tstring_content":
            return None

        pieces.append(text)
        index += 1

    if index >= len(tokens):
        return None

    return "".join(pieces)


def _require_calls(tokens):
    found = []
    for index, (event, text, line) in enumerate(tokens):
        if event != "on_ident" or text not in {"require", "require_relative"}:
            continue

        name = _literal_string(tokens, index + 1)

        if name:
            found.append((text, name, line))

    return found


def _definition_events(tokens):
    events = []
    for index, (event, text, line) in enumerate(tokens):
        if event != "on_kw" or text not in {"def", "class", "module"}:
            continue

        next_index = _significant(tokens, index + 1)

        if next_index >= len(tokens):
            continue

        name_event, name, _name_line = tokens[next_index]

        if name_event not in {"on_ident", "on_const", "on_op", "on_kw"}:
            continue

        singleton = False
        if text == "def" and name == "self":
            method_index = _significant(tokens, next_index + 1)
            if method_index < len(tokens) and tokens[method_index][0] == "on_period":
                method_index = _significant(tokens, method_index + 1)
                if method_index < len(tokens):
                    name = tokens[method_index][1]
                    singleton = True

        events.append({"keyword": text, "name": name, "line": line, "singleton": singleton})

    return events


def _constant_name(node):
    if not isinstance(node, list) or not node:
        return None

    kind = node[0]
    if kind == "@const":
        return node[1]
    if kind in {"const_ref", "top_const_ref"} and len(node) > 1:
        return _constant_name(node[1])
    if kind == "const_path_ref" and len(node) > 2:
        left = _constant_name(node[1])
        right = _constant_name(node[2])
        if left and right:
            return f"{left}::{right}"
        return right or left

    return None


def _symbols(path, tokens, tree):
    events = _definition_events(tokens)
    result = []
    event_index = 0

    def walk(node, parent=None):
        nonlocal event_index
        if not isinstance(node, list) or not node:
            return
        if not isinstance(node[0], str):
            for child in node:
                walk(child, parent)
            return

        kind = node[0]
        next_parent = parent

        if kind in {"class", "module", "def", "defs"} and event_index < len(events):
            event = events[event_index]
            event_index += 1
            if kind == "class":
                name = _constant_name(node[1]) if len(node) > 1 else None
                symbol_kind = "class"
            elif kind == "module":
                name = _constant_name(node[1]) if len(node) > 1 else None
                symbol_kind = "module"
            elif kind == "defs":
                name_node = node[3] if len(node) > 3 else None
                name = name_node[1] if isinstance(name_node, list) and len(name_node) > 1 else event["name"]
                symbol_kind = "method"
            else:
                name_node = node[1] if len(node) > 1 else None
                name = name_node[1] if isinstance(name_node, list) and len(name_node) > 1 else event["name"]
                symbol_kind = "method" if parent or event["singleton"] else "function"

            if name:
                metadata = {"singleton": True} if event["singleton"] or kind == "defs" else {}
                result.append(Symbol(name, symbol_kind, str(path), event["line"], parent, metadata))
                next_parent = f"{parent}.{name}" if parent else name

        for child in node[1:]:
            walk(child, next_parent)

    walk(tree)

    return result


@lru_cache(maxsize=1)
def _load_path():
    ruby = shutil.which("ruby")

    if ruby is None:
        return ()

    try:
        result = subprocess.run(
            [ruby, "-e", "puts $LOAD_PATH"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ()

    if result.returncode != 0:
        return ()

    return tuple(Path(line) for line in result.stdout.splitlines() if line)


def _resolve_require(path, kind, name):
    base = Path(name)
    candidates = []

    if kind == "require_relative":
        candidates.append(path.parent / base)
    else:
        for root in _load_path():
            candidates.append(root / base)

    expanded = []

    for candidate in candidates:
        expanded.append(candidate)
        if candidate.suffix != ".rb":
            expanded.append(candidate.with_suffix(".rb"))
        expanded.append(candidate / "init.rb")

    for candidate in expanded:
        if candidate.is_file():
            return candidate.resolve()

    return None


class RubyAnalyzer(Analyzer):
    """Read Ruby definitions and literal require relationships via Ripper."""

    name = "ruby"
    kinds = ("ruby",)

    def symbols(self, path):
        path, data = _parse(path)
        return [
            Symbol(
                item["name"], item["kind"], str(path), item["line"],
                item.get("parent"), item.get("metadata", {}),
            )
            for item in data["symbols"]
        ]

    def edges(self, path):
        path, data = _parse(path)
        found = []

        for item in data["requires"]:
            kind, name = item["kind"], item["name"]
            target = _resolve_require(path, kind, name)

            if target is None:
                found.append(
                    Edge(str(path), None, "imports", "unresolved", name=name)
                )
            else:
                found.append(
                    Edge(
                        str(path),
                        str(target),
                        "imports",
                        "resolved",
                        name=name,
                    )
                )

        return found


if "ruby" not in registry.names():
    registry.register(RubyAnalyzer())
