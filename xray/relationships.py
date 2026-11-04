import ast
from dataclasses import dataclass
from pathlib import Path

from .dependencies import discover_local_modules
from .references import (
    _find_module_file,
    _find_symbol,
    _resolve,
    find_references,
)
from .symbols import extract_symbols_from_source


@dataclass(frozen=True)
class Relationship:
    """A static relationship from a class or function to a name.

    kind is "inherits" or "calls".
    source is the qualified name of the class or function that
    contains the relationship ("Child", "User.save").
    name is the name as written ("Base", "self.validate").
    status is "resolved", "unresolved" or "external".
    target is "relative/path.py:Name" when status is "resolved".
    """

    kind: str
    source: str
    name: str
    line: int
    file: str
    status: str
    target: str | None = None


def _location(path, project_root):
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return str(path)


def find_relationships(path, project_root=None):
    """Return inheritance and call relationships found in a file.

    Static and conservative. Recorded:
      - class bases written as plain names
      - calls to plain names that are defined at module level in the
        same file or imported with "from X import name"
      - self.method() calls to a method of the same class

      - module.function() calls after "import module", "import module as alias"
        or "import pkg.sub", when the module is part of the project

    Not recorded: module-level calls, attribute calls such as
    obj.method(), calls to external modules, calls to builtins or to
    local variables, and inherited methods.
    """

    # Raises FileError / AnalysisError for unreadable or invalid files.
    references = find_references(path, project_root)

    file = str(path)
    path = Path(path).resolve()

    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    tree = ast.parse(source, filename=file)

    if project_root is None:
        project_root = path.parent

    project_root = Path(project_root).resolve()
    location = _location(path, project_root)

    imported = {}

    for reference in references:
        imported.setdefault(reference.name, reference)

    symbols = extract_symbols_from_source(source, file)

    top_level = {
        symbol.name
        for symbol in symbols
        if symbol.parent is None
        and symbol.kind in ("function", "class")
    }

    methods = {}

    for symbol in symbols:
        if symbol.kind == "method":
            methods.setdefault(symbol.parent, set()).add(
                symbol.name
            )

    module_aliases = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    module_aliases[alias.asname] = alias.name
                else:
                    module_aliases[alias.name] = alias.name
                    first = alias.name.split(".")[0]
                    module_aliases.setdefault(first, first)

    local_modules = discover_local_modules(project_root)

    module_files = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue

        if node.level:
            base_dir = path.parent

            for _ in range(node.level - 1):
                base_dir = base_dir.parent
        else:
            base_dir = project_root

        for alias in node.names:
            if alias.name == "*":
                continue

            dotted_name = (
                f"{node.module}.{alias.name}"
                if node.module
                else alias.name
            )
            found_file = _find_module_file(base_dir, dotted_name)

            if found_file is not None:
                module_files[alias.asname or alias.name] = found_file

    def dotted(node):
        parts = []

        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value

        if isinstance(node, ast.Name):
            parts.append(node.id)

            return ".".join(reversed(parts))

        return None

    found = []

    def resolve(name):
        if name in top_level:
            return "resolved", f"{location}:{name}"

        if name in imported:
            reference = imported[name]
            return reference.status, reference.target

        return None

    def add(kind, source_name, label, node, outcome):
        status, target = outcome

        found.append(
            (
                node.lineno,
                node.col_offset,
                Relationship(
                    kind,
                    source_name,
                    label,
                    node.lineno,
                    file,
                    status,
                    target,
                ),
            )
        )

    def scan_calls(function, qualified, owner):
        for statement in function.body:
            for node in ast.walk(statement):
                if not isinstance(node, ast.Call):
                    continue

                callee = node.func

                if isinstance(callee, ast.Name):
                    outcome = resolve(callee.id)

                    if outcome:
                        add(
                            "calls",
                            qualified,
                            callee.id,
                            node,
                            outcome,
                        )

                elif (
                    isinstance(callee, ast.Attribute)
                    and isinstance(callee.value, ast.Name)
                    and callee.value.id == "self"
                    and owner is not None
                    and callee.attr in methods.get(owner, set())
                ):
                    add(
                        "calls",
                        qualified,
                        f"self.{callee.attr}",
                        node,
                        (
                            "resolved",
                            f"{location}:{owner}.{callee.attr}",
                        ),
                    )

                elif isinstance(callee, ast.Attribute):
                    base = dotted(callee.value)

                    if base in module_files:
                        module_file = module_files[base]
                        symbol = _find_symbol(module_file, callee.attr)

                        if symbol is None:
                            outcome = ("unresolved", None)
                        else:
                            outcome = (
                                "resolved",
                                f"{_location(module_file, project_root)}:{symbol.name}",
                            )

                        add(
                            "calls",
                            qualified,
                            f"{base}.{callee.attr}",
                            node,
                            outcome,
                        )

                    elif base in module_aliases:
                        status, target = _resolve(
                            path,
                            project_root,
                            local_modules,
                            module_aliases[base],
                            0,
                            callee.attr,
                        )

                        if status != "external":
                            add(
                                "calls",
                                qualified,
                                f"{base}.{callee.attr}",
                                node,
                                (status, target),
                            )

    def scan(body, parent):
        for node in body:
            if isinstance(node, ast.ClassDef):
                qualified = (
                    f"{parent}.{node.name}"
                    if parent
                    else node.name
                )

                for base in node.bases:
                    if isinstance(base, ast.Name):
                        outcome = resolve(base.id)

                        if outcome:
                            add(
                                "inherits",
                                qualified,
                                base.id,
                                base,
                                outcome,
                            )

                scan(node.body, qualified)

            elif isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                qualified = (
                    f"{parent}.{node.name}"
                    if parent
                    else node.name
                )

                scan_calls(node, qualified, parent)

    scan(tree.body, None)

    found.sort(key=lambda item: (item[0], item[1]))

    return [relationship for _, _, relationship in found]
