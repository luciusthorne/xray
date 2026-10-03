import ast
from pathlib import Path

from .symbols import Symbol
from .unused import _used_names


def _attribute_names(tree):
    return {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    }


def _string_values(tree):
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
    }


def _reexported_names(tree):
    names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.name)

    return names


def _definitions(tree):
    found = []

    def walk(body, parent, inherited):
        for node in body:
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                found.append(
                    (
                        node.lineno,
                        node.col_offset,
                        node.name,
                        "method" if parent else "function",
                        parent,
                        bool(node.decorator_list),
                        inherited,
                    )
                )

            elif isinstance(node, ast.ClassDef):
                found.append(
                    (
                        node.lineno,
                        node.col_offset,
                        node.name,
                        "class",
                        parent,
                        bool(node.decorator_list),
                        False,
                    )
                )

                qualified = (
                    f"{parent}.{node.name}"
                    if parent
                    else node.name
                )

                has_bases = bool(node.keywords) or any(
                    not (
                        isinstance(base, ast.Name)
                        and base.id == "object"
                    )
                    for base in node.bases
                )

                walk(node.body, qualified, has_bases)

    walk(tree.body, None, False)

    found.sort(key=lambda item: (item[0], item[1]))

    return found


def _is_exempt_file(name):
    return (
        name in ("__init__.py", "conftest.py", "setup.py")
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def find_unused_symbols(project_root):
    """Return functions, classes and methods that appear unused.

    Scans every Python file under project_root. A definition counts
    as used if its name appears anywhere in the project as a plain
    name, as an attribute (obj.name, module.name), as an exact string
    (getattr(obj, "name")), in an __all__ list, in a string
    annotation, or imported by an __init__.py (a re-export).

    Matching is by name, not by resolved target, so two unrelated
    definitions with the same name hide each other. A recursive
    function counts as used by itself.

    Never reported: names in __init__.py, conftest.py, setup.py and
    test files; dunder methods; "main"; decorated definitions;
    methods of classes with base classes (frameworks may call them);
    module-level variables.

    Files that cannot be read or parsed are skipped. Results are
    candidates, not proof: dynamic use and public APIs used from
    outside the project are not visible.
    """

    project_root = Path(project_root).resolve()

    parsed = []

    for path in sorted(project_root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue

        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, ValueError):
            continue

        parsed.append(
            (path.relative_to(project_root).as_posix(), path.name, tree)
        )

    used = set()

    for _, name, tree in parsed:
        used |= _used_names(tree)
        used |= _attribute_names(tree)
        used |= _string_values(tree)

        if name == "__init__.py":
            used |= _reexported_names(tree)

    unused = []

    for relative, name, tree in parsed:
        if _is_exempt_file(name):
            continue

        for (
            line,
            _,
            definition,
            kind,
            parent,
            decorated,
            inherited,
        ) in _definitions(tree):
            if decorated or definition in used:
                continue

            if definition.startswith("__") and definition.endswith(
                "__"
            ):
                continue

            if kind == "function" and definition == "main":
                continue

            if kind == "method" and inherited:
                continue

            unused.append(
                Symbol(definition, kind, relative, line, parent)
            )

    return unused
