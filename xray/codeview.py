import ast
import subprocess
from pathlib import Path

from xray import command_analyzers, python_analyzer  # noqa: F401
from xray.analyzers import registry
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
    AST end line; other named script symbols return a bounded excerpt from
    their definition line. Other files return their text.
    """

    path = Path(path)
    kind = command_kind(path)

    if kind == "elf":
        if name is None or name.endswith((".c", ".h")):
            lines = files_lines(path, name, say=say)
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
            return _assembly_fallback(path, lines, name)

        if asm:
            lines += ["", "Disassembly:", *function_lines(path, name)]

        return lines

    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
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
    elif kind == "shell":
        line = shell_function_lines(path).get(name)
    elif kind == "perl":
        line = dict(scan_perl(path).subs).get(name)
    elif kind in {"ruby", "javascript", "lua", "typescript", "c"}:
        analyzer = registry.analyzer_for(path)
        line = next(
            (symbol.line for symbol in analyzer.symbols(path) if symbol.name == name),
            None,
        )
    else:
        line = None

    if line is None:
        return [f"No function named {name[:60]} in this script"]

    return _numbered(text[line - 1:], start=line, limit=60)


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
