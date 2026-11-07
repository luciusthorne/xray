"""--browse: a terminal menu over the views XRAY already has.

It adds no analysis of its own. Each entry prints an existing view
(overview, functions and their code, calls, chain, toolchain), so the
menu and the separate options always agree. It needs a terminal, and
--serve remains the browser view of the same data.
"""

from pathlib import Path

from xray.entrypoints import command_kind

PAGE = 40


def function_names(path, kind):
    """Names --code accepts for this file (outer definitions first)."""

    if kind == "elf":
        from xray import codemap

        try:
            cmap = codemap.code_map(path)
        except (OSError, ValueError):
            cmap = None
        if cmap is not None and cmap.files:
            # Readable names, the program's own first (in file and line order), then the rest.
            def rank(function):
                group = codemap._origin(cmap, function.file)[0] if function.file else "program"
                return (codemap._GROUP_ORDER.get(group, 9), function.file or "~", function.line or 0)

            return list(dict.fromkeys(
                codemap._base(function.name) or function.name
                for function in sorted(cmap.functions, key=rank)
                if not codemap._is_cold(function)
            ))
        from xray.minidebug import debuginfod_function_table, read_function_table

        return list(dict.fromkeys(entry[2] for entry in read_function_table(path) or debuginfod_function_table(path)))

    if kind == "python":
        import ast

        tree = ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"))
        return [
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]

    if kind == "shell":
        from xray.shellscan import function_lines

        return list(function_lines(path))

    if kind == "perl":
        from xray.perlscan import scan_perl

        return [name for name, _line in scan_perl(path).subs]

    from xray.analyzers import analyzer_for

    analyzer = analyzer_for(Path(path))

    if analyzer is None:
        return []

    return list(dict.fromkeys(symbol.name for symbol in analyzer.symbols(path)))


def _views(path, kind):
    from xray.calls import calls_lines
    from xray.chain import chain_lines
    from xray.report import report_lines

    views = [
        ("Overview", lambda: report_lines(path)),
        ("Functions", None),
        ("Calls", lambda: calls_lines(path)),
        ("Chain", lambda: chain_lines(path)),
    ]

    if kind == "shell":
        def shell_callgraph():
            from xray.scriptgraph import callgraph_lines, shell_graph

            graph = shell_graph(path)
            return callgraph_lines(graph, Path(path).name) if graph else ["Could not parse this script"]

        views.append(("Call graph", shell_callgraph))

    if kind == "lisp":
        def lisp_callgraph():
            from xray.scriptgraph import callgraph_lines, lisp_graph

            graph = lisp_graph(path)
            return callgraph_lines(graph, Path(path).name) if graph else ["No Lisp forms read"]

        views.append(("Call graph", lisp_callgraph))

    if kind in ("perl", "ruby", "javascript", "typescript", "lua"):
        def named_callgraph():
            from xray.scriptgraph import callgraph_lines, symbol_graph

            graph = symbol_graph(path, kind)
            return (["Calls found by name (name( / obj.name( / bare names in Perl and Ruby)", ""]
                    + callgraph_lines(graph, Path(path).name)) if graph else ["No functions found"]

        views.append(("Call graph", named_callgraph))

    if kind == "elf":
        from xray.fingerprint import toolchain_lines
        from xray.uses import uses_lines

        def callgraph():
            from xray.codemap import elf_callgraph

            return elf_callgraph(path) or ["No function names in this binary"]

        views += [
            ("Call graph", callgraph),
            ("Toolchain", lambda: toolchain_lines(path)),
            ("Uses", lambda: uses_lines(path)),
        ]

    return views


def browse(path, read=input, write=print):
    """Run the menu until the user quits or input ends."""

    from xray.codeview import code_lines

    path = Path(path)
    kind = command_kind(path)
    views = _views(path, kind)
    names = None

    def ask(prompt):
        try:
            return read(prompt).strip()
        except EOFError:
            return "q"

    while True:
        write("")
        write(f"{path.name} ({kind})")
        for number, (label, _view) in enumerate(views, start=1):
            write(f"  {number}. {label}")
        write("  q. Quit")
        choice = ask("Choose: ")

        if choice in ("q", "quit", "exit"):
            return

        if not choice.isdigit() or not 1 <= int(choice) <= len(views):
            write(f"Unknown choice: {choice[:20]}")
            continue

        label, view = views[int(choice) - 1]

        if view is not None:
            write("")
            for line in view():
                write(line)
            continue

        if names is None:
            names = function_names(path, kind)

        if not names:
            write("No function names found in this file.")
            continue

        start = 0
        while True:
            write("")
            shown = names[start:start + PAGE]
            for number, name in enumerate(shown, start=start + 1):
                write(f"  {number}. {name}")
            more = start + PAGE < len(names)
            write("  Type a number or a name" + (", n for more" if more else "") + ", b to go back")
            pick = ask("Function: ")

            if pick in ("b", "back", ""):
                break
            if pick in ("q", "quit"):
                return
            if pick == "n" and more:
                start += PAGE
                continue

            name = names[int(pick) - 1] if pick.isdigit() and 1 <= int(pick) <= len(names) else pick
            write("")
            for line in code_lines(path, name):
                write(line)
