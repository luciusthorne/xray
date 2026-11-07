import ast
import subprocess
from pathlib import Path

from xray import command_analyzers, python_analyzer  # noqa: F401
from xray.disasm import assembly_lines
from xray.entrypoints import command_kind
from xray.perlscan import scan_perl
from xray.rizinview import function_lines
from xray.shellscan import function_lines as shell_function_lines
from xray.sourcelookup import files_lines, source_lines


def _numbered(lines, start=1, limit=400):
    shown = [f"{n:5d}  {line}" for n, line in enumerate(lines[:limit], start)]

    if len(lines) > limit:
        shown.append(f"... and {len(lines) - limit} more lines")

    return shown


def _python_definition(lines, name):
    """Return the source span for a named Python function or class."""

    tree = ast.parse("\n".join(lines))
    matches = []

    def visit(body, parent=""):
        for node in body:
            if isinstance(node, ast.ClassDef):
                qualified = f"{parent}.{node.name}" if parent else node.name
                if name in (node.name, qualified):
                    matches.append((qualified, node))
                visit(node.body, qualified)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{parent}.{node.name}" if parent else node.name
                if name in (node.name, qualified):
                    matches.append((qualified, node))

    visit(tree.body)
    exact = next((node for qualified, node in matches if qualified == name), None)
    node = exact or (matches[0][1] if matches else None)

    if node is None:
        return None

    start = min(
        [node.lineno, *(decorator.lineno for decorator in node.decorator_list)]
    )
    return start, node.end_lineno


def code_lines(path, name=None, asm=False, say=lambda text: None):
    """Return the code of a command, whatever kind it is.

    ELF binaries: source files, or the C source of a function (plus its
    disassembly with asm). Python definitions are returned through their
    AST end line; other named script symbols through the end line their
    parser reports or, for shell and Perl, their matching closing brace.
    Other files return their text.
    """

    path = Path(path)
    kind = command_kind(path)

    if kind == "elf":
        from xray.codemap import SOURCE_SUFFIXES

        if name is not None and name.endswith(SOURCE_SUFFIXES) and not name.endswith((".c", ".h")):
            mapped = _code_map_view(path, name, say)
            if mapped is not None:
                return mapped
        if name is None or name.endswith((".c", ".h")):
            lines = files_lines(path, name, say=say)
            if _source_unavailable(lines):
                mapped = _code_map_view(path, name, say)
                if mapped is not None:
                    return mapped
            if name is None and _source_unavailable(lines):
                try:
                    from xray.debuginfod import configured, function_names

                    if configured():
                        say("Querying configured debuginfod servers for function names")
                        names = function_names(path)
                        if names:
                            limit = 80
                            from xray.minidebug import read_function_table

                            known = {
                                entry[2] for entry in read_function_table(path)
                            }
                            preferred = [
                                name for name in ("main", "_start") if name in names
                            ]
                            retained = [
                                name for name in names
                                if name in known and name not in preferred
                            ]
                            ordered = preferred + retained + [
                                name for name in names
                                if name not in preferred and name not in retained
                            ]
                            return [
                                *lines,
                                "",
                                f"Functions available from debuginfod ({len(names)}):",
                                *(f"- {item}" for item in ordered[:limit]),
                                *(
                                    [f"- ... and {len(names) - limit} more"]
                                    if len(names) > limit
                                    else []
                                ),
                                "",
                                "Read one with --code <function name>.",
                            ]
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                    pass
                return _assembly_fallback(path, lines)
            return lines

        lines = source_lines(path, name, say=say)

        if _source_unavailable(lines):
            mapped = _code_map_view(path, name, say)
            if mapped is not None:
                if asm:
                    mapped += ["", "Disassembly:", *function_lines(path, name)]
                return mapped
            return _assembly_fallback(path, lines, name)

        if asm:
            lines += ["", "Disassembly:", *function_lines(path, name)]

        return lines

    try:
        if kind == "lisp":
            from xray.lisp import read_text

            text = read_text(path).splitlines()  # also .el.gz
        else:
            text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, EOFError):
        return [f"Unable to read {path}"]

    if name is None:
        return _numbered(text)

    if kind == "python":
        span = _python_definition(text, name)
        if span is None:
            line = None
        else:
            start, end = span
            return _numbered(text[start - 1 : end], start=start, limit=400)
    end = None

    if kind == "shell":
        line = shell_function_lines(path).get(name)
        end = _brace_end(text, line)
    elif kind == "perl":
        line = dict(scan_perl(path).subs).get(name)
        end = _brace_end(text, line)
    elif kind in {"ruby", "javascript", "lua", "typescript", "c", "lisp"}:
        from xray.analyzers import analyzer_for

        analyzer = analyzer_for(path)
        symbol = next(
            (symbol for symbol in analyzer.symbols(path) if symbol.name == name),
            None,
        )
        line = symbol.line if symbol else None
        end = symbol.metadata.get("end_line") if symbol else None
    else:
        line = None

    if line is None:
        return [f"No function named {name[:60]} in this script"]

    if end is None or end < line:
        shown = _numbered(text[line - 1:], start=line, limit=60)
        return [*shown, "(end of definition not found: showing up to 60 lines)"]

    return _numbered(text[line - 1 : end], start=line, limit=400)


def _brace_end(lines, line):
    """Return the line holding the brace that closes the body opened at line.

    Quotes and comments are skipped so braces inside them do not count.
    """

    if line is None:
        return None

    depth = 0
    opened = False
    quote = None

    for number in range(line, len(lines) + 1):
        text = lines[number - 1]
        index = 0

        while index < len(text):
            ch = text[index]

            if quote:
                if ch == "\\" and quote != "'":
                    index += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch == "\\":
                index += 2
                continue
            elif ch in "'\"`":
                quote = ch
            elif ch == "#" and (index == 0 or text[index - 1] in " \t;{}"):
                break
            elif ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return number

            index += 1

        if not opened and number > line + 1:
            return None

    return None


def _code_map_view(path, name, say):
    """--code through the code map (any DWARF language: C, C++, Rust, ...), or None."""

    from xray import codemap

    try:
        say("Building the code map (function names and source lines)")
        cmap = codemap.code_map(path)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        return None
    if cmap is None:
        return None
    label = path.name
    if name is None:
        return codemap.overview_lines(cmap, label)
    if name.endswith(codemap.SOURCE_SUFFIXES):
        view = codemap.file_view(cmap, name, label)
        if view is not None:
            return view
    view = codemap.function_view(cmap, name, label)
    if view is None and cmap.go is not None:
        # Machine code of a whole Go binary helps no one; the function was probably inlined.
        return [(f"No function named {name!r} in {label}'s function table: the compiler may have inlined it, "
                "or the name differs."),
                f"See the map: xray {label} --code   ·   a file's functions: xray {label} --code FILE.go"]
    return view


def _source_unavailable(lines):
    if not lines:
        return True
    return any(
        line.startswith((
            "No function names in this binary",
            "Unknown function:",
            "No source files found",
            "Source not available:",
            "Could not fetch the source package:",
            "Package ",
            "No installed package owns this file",
        ))
        or "source package lookup currently supports RPM" in line
        for line in lines[:2]
    )


def _assembly_fallback(path, reason, name=None):
    assembly = assembly_lines(path, name=name)
    heading = "Source is unavailable; showing ELF disassembly instead:"
    if name is not None and assembly and assembly[0].startswith("No disassembly label"):
        heading = "The requested symbol has no label; showing bounded ELF disassembly:"
        assembly = assembly_lines(path)
    return [
        *reason,
        "",
        heading,
        *assembly,
    ]
