"""Call graphs of shell scripts: which function calls which, and which commands
each one runs, with line numbers.

Built from the full shell parser (xray/shparse.py): every command (also inside
$(...), eval strings, trap and sh -c) is attributed to the innermost function
whose body contains its line; calls to the script's own functions become
function -> function edges, everything else is an external command or a
sourced file.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

TOP = "(top level)"


@dataclass
class ScriptGraph:
    path: Path
    functions: dict                                    # name -> (start, end)
    calls: dict = field(default_factory=dict)          # caller -> {callee function: [lines]}
    commands: dict = field(default_factory=dict)       # caller -> {command: [lines]}
    sources: dict = field(default_factory=dict)        # caller -> {file: [lines]}
    dynamic: int = 0


def shell_graph(path):
    """ScriptGraph for a shell script, or None when it cannot be parsed."""

    from xray.codeview import _brace_end
    from xray.shellscan import _Reader
    from xray.shparse import parse

    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        result = parse(text)
    except (OSError, RecursionError, ValueError, IndexError, AttributeError):
        return None
    lines = text.splitlines()
    spans = {}
    starts = sorted(dict(result.functions).items(), key=lambda item: item[1])
    for index, (name, start) in enumerate(starts):
        end = _brace_end(lines, start)
        if end is None or end == start:
            # Unbalanced quotes in a heredoc defeat the brace matcher: use the next "}" in column 0.
            end = next((n for n in range(start + 1, len(lines) + 1) if lines[n - 1].rstrip() == "}"), start)
        following = starts[index + 1][1] if index + 1 < len(starts) else None
        if following is not None and end >= following:
            # A heredoc or odd quoting fooled the brace matcher; nested shell functions are rare.
            end = following - 1
            while end > start and not lines[end - 1].strip().startswith("}"):
                end -= 1
        spans[name] = (start, end)

    def owner(line):
        inside = [(end - start, name) for name, (start, end) in spans.items() if start <= line <= end]
        return min(inside)[1] if inside else TOP

    graph = ScriptGraph(path, spans)
    calls = defaultdict(lambda: defaultdict(list))
    commands = defaultdict(lambda: defaultdict(list))
    sources = defaultdict(lambda: defaultdict(list))
    for command in result.commands:
        reader = _Reader(result.assignments)
        try:
            reader.words(list(command.words), command.line)
        except (RecursionError, ValueError, IndexError, AttributeError):
            continue
        caller = owner(command.line)
        first = command.words[0] if command.words else None
        if first is not None and first.static and first.value in spans and first.value not in reader.commands:
            # The script's own function, even when it shares a builtin's name (help, test, ...).
            calls[caller][first.value].append(command.line)
        for name in reader.commands:
            target = calls if name in spans else commands
            if target is calls and name == caller and spans[name][0] == command.line:
                continue
            target[caller][name].append(command.line)
        for name in reader.sources:
            sources[caller][name].append(command.line)
        graph.dynamic += len(reader.dynamic)
    graph.calls = {k: {n: sorted(set(v)) for n, v in d.items()} for k, d in calls.items()}
    graph.commands = {k: {n: sorted(set(v)) for n, v in d.items()} for k, d in commands.items()}
    graph.sources = {k: {n: sorted(set(v)) for n, v in d.items()} for k, d in sources.items()}
    return graph


def _where(lines):
    shown = ", ".join(str(line) for line in lines[:6])
    return f"line {shown}" if len(lines) == 1 else f"lines {shown}" + (", …" if len(lines) > 6 else "")


def callgraph_lines(graph, name, focus=None, per_function=20):
    """Text view: every function with what it calls, or one function in both directions."""

    def start(function):
        return graph.functions[function][0] if function in graph.functions else 0

    callers_of = defaultdict(dict)
    for caller, callees in graph.calls.items():
        for callee, lines in callees.items():
            callers_of[callee][caller] = lines

    def block(function, both=False):
        out = [f"{function}" + (f"  (lines {graph.functions[function][0]}–{graph.functions[function][1]})"
                                if function in graph.functions else "")]
        callees = graph.calls.get(function, {})
        for callee in sorted(callees, key=start)[:per_function]:
            out.append(f"  → {callee}  (defined at line {start(callee)}; called at {_where(callees[callee])})")
        if len(callees) > per_function:
            out.append(f"  ... and {len(callees) - per_function} more functions")
        commands = graph.commands.get(function, {})
        if commands:
            names = sorted(commands)
            out.append(f"  runs {len(names)} command(s): " + ", ".join(names[:per_function])
                       + (" …" if len(names) > per_function else ""))
        for file, lines in sorted(graph.sources.get(function, {}).items()):
            out.append(f"  sources {file}  ({_where(lines)})")
        if both:
            into = callers_of.get(function, {})
            out.append(f"  called by ({len(into)}):")
            for caller in sorted(into, key=start):
                out.append(f"    ← {caller}  ({_where(into[caller])})")
            if not into:
                out.append("    nothing (unused, or run through a variable or eval)")
            for command in sorted(commands):
                out.append(f"    {command}: {_where(commands[command])}")
        return out

    if focus is not None:
        if focus not in graph.functions and focus != TOP:
            names = ", ".join(sorted(graph.functions)[:30])
            return [f"No function named {focus!r} in {name}. Functions: {names}"]
        return block(focus, both=True)

    edges = sum(len(callees) for callees in graph.calls.values())
    unused = sorted(f for f in graph.functions if f not in callers_of)
    lines = [f"{len(graph.functions)} functions, {edges} call(s) between them"
             + (f"; {graph.dynamic} command(s) built at run time are not followed" if graph.dynamic else ""), ""]
    for function in [TOP] + sorted(graph.functions, key=start):
        if function == TOP and not (graph.calls.get(TOP) or graph.commands.get(TOP) or graph.sources.get(TOP)):
            continue
        lines += block(function) + [""]
    if unused:
        lines.append("Not called by any function or the top level: " + ", ".join(unused))
        lines.append("(they may still run through a variable, eval, trap or another script)")
    lines.append(f"One function, both directions: xray {name} --callgraph FUNCTION")
    return lines


# -- other script languages: calls found by name ------------------------------

_COMMENTS = {
    "perl": ("#", None),
    "ruby": ("#", ("=begin", "=end")),
    "javascript": ("//", ("/*", "*/")),
    "typescript": ("//", ("/*", "*/")),
    "lua": ("--", ("--[[", "]]")),
}


def _blank_comments_and_strings(lines, kind):
    """Lines of the same length with comments and string contents replaced by spaces,
    so a function name inside a string or comment is not read as a call."""

    line_comment, block = _COMMENTS.get(kind, ("#", None))
    quotes = "\"'`" if kind in ("javascript", "typescript") else "\"'"
    out, in_block = [], False
    for text in lines:
        chars, i, n = list(text), 0, len(text)
        if in_block:
            end = text.find(block[1])
            if end < 0:
                out.append(" " * n)
                continue
            for j in range(end + len(block[1])):
                chars[j] = " "
            i, in_block = end + len(block[1]), False
        quote = None
        while i < n:
            if quote:
                if text[i] == "\\":
                    chars[i] = " "
                    if i + 1 < n:
                        chars[i + 1] = " "
                    i += 2
                    continue
                if text[i] == quote:
                    quote = None
                else:
                    chars[i] = " "
                i += 1
                continue
            if block and text.startswith(block[0], i):
                end = text.find(block[1], i + len(block[0]))
                stop = n if end < 0 else end + len(block[1])
                for j in range(i, stop):
                    chars[j] = " "
                in_block = end < 0
                i = stop
                continue
            if text.startswith(line_comment, i) and not (kind == "perl" and i and text[i - 1] == "$"):
                for j in range(i, n):
                    chars[j] = " "
                break
            if text[i] in quotes and not (kind == "perl" and text[i] == "'" and i and text[i - 1].isalnum()):
                quote = text[i]
            i += 1
        out.append("".join(chars))
    return out


def symbol_graph(path, kind):
    """ScriptGraph for a Perl, Ruby, JavaScript, TypeScript or Lua file, from its
    function definitions and calls to them found by name (`name(`, `obj.name(`,
    Perl `&name`), with comments and strings blanked. None without functions."""

    import re

    from xray import command_analyzers, python_analyzer  # noqa: F401  (register analyzers)
    from xray.analyzers import analyzer_for
    from xray.codeview import _brace_end

    path = Path(path)
    analyzer = analyzer_for(path)
    if analyzer is None:
        return None
    try:
        symbols = [s for s in analyzer.symbols(path) if s.kind in ("function", "method")]
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError, RuntimeError):
        return None
    if not symbols:
        return None
    spans = {}
    for symbol in symbols:
        text = lines[symbol.line - 1].strip() if 0 < symbol.line <= len(lines) else ""
        if kind == "perl" and text.endswith(";") and "{" not in text:
            continue  # a forward declaration (sub name ($$);), not the definition
        end = symbol.metadata.get("end_line") if symbol.metadata else None
        if not end and kind in ("perl", "javascript", "typescript"):
            end = _brace_end(lines, symbol.line)
        span = (symbol.line, max(end or symbol.line, symbol.line))
        if symbol.name not in spans or span[1] - span[0] > spans[symbol.name][1] - spans[symbol.name][0]:
            spans[symbol.name] = span
    if not spans:
        return None
    clean = _blank_comments_and_strings(lines, kind)
    names = sorted(spans, key=len, reverse=True)
    pattern = re.compile(r"(?<![\w$])&?(" + "|".join(re.escape(name) for name in names) + r")\s*\(")
    alternatives = "|".join(re.escape(name) for name in names)
    perl_bare = re.compile(r"(?<![\w$])&(" + alternatives + r")\b") if kind == "perl" else None
    # Perl and Ruby call functions without parentheses too (parse_arguments;  helper arg).
    # Not after a sigil, ->, ::, . or a symbol colon; not a hash key (name => / {name}).
    bare = re.compile(r"(?<![\w$@%&>:.{])(" + alternatives + r")\b(?!\s*=>)(?!\s*\})(?!\s*:[^:])") \
        if kind in ("perl", "ruby") else None

    def owner(line):
        inside = [(end - start, name) for name, (start, end) in spans.items() if start <= line <= end]
        return min(inside)[1] if inside else TOP

    calls = defaultdict(lambda: defaultdict(list))
    for number, text in enumerate(clean, 1):
        found = {m.group(1) for m in pattern.finditer(text)}
        if perl_bare:
            found |= {m.group(1) for m in perl_bare.finditer(text)}
        if bare:
            found |= {m.group(1) for m in bare.finditer(text)}
        for callee in found:
            if spans[callee][0] == number or re.search(
                rf"\b(?:sub|def|function|fn)\s+(?:[\w.:]+[.:])?{re.escape(callee)}\b", text
            ):
                continue  # a definition or declaration, not a call
            calls[owner(number)][callee].append(number)
    graph = ScriptGraph(path, spans)
    graph.calls = {k: {n: sorted(set(v)) for n, v in d.items()} for k, d in calls.items()}
    return graph
