import ast
from dataclasses import dataclass
from pathlib import Path

from .errors import AnalysisError, FileError


@dataclass(frozen=True)
class UnusedImport:
    """An import whose bound name does not appear to be used.

    name is the name the import binds ("np" for "import numpy as np",
    "os" for "import os.path").
    module is the module imported, or imported from ("numpy",
    "os.path", ".utils").

    This is a static heuristic, not proof. See find_unused_imports.
    """

    name: str
    module: str
    line: int
    file: str


def _annotation_strings(annotation, names):
    for node in ast.walk(annotation):
        if isinstance(node, ast.Constant) and isinstance(
            node.value, str
        ):
            try:
                parsed = ast.parse(node.value, mode="eval")
            except SyntaxError:
                continue

            for child in ast.walk(parsed):
                if isinstance(child, ast.Name):
                    names.add(child.id)


def _string_items(value, names):
    if isinstance(value, (ast.List, ast.Tuple)):
        for element in value.elts:
            if isinstance(element, ast.Constant) and isinstance(
                element.value, str
            ):
                names.add(element.value)


def _used_names(tree):
    names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(
            node.ctx, (ast.Load, ast.Del)
        ):
            names.add(node.id)

        elif isinstance(node, ast.arg):
            if node.annotation is not None:
                _annotation_strings(node.annotation, names)

        elif isinstance(node, ast.AnnAssign):
            _annotation_strings(node.annotation, names)

        elif isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            if node.returns is not None:
                _annotation_strings(node.returns, names)

        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and (
                    target.id == "__all__"
                ):
                    _string_items(node.value, names)

        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and (
                node.target.id == "__all__"
            ):
                _string_items(node.value, names)

    return names


def _imports(tree):
    found = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]

                found.append(
                    (node.lineno, node.col_offset, bound, alias.name)
                )

        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__" and not node.level:
                continue

            module = "." * node.level + (node.module or "")

            for alias in node.names:
                if alias.name == "*":
                    continue

                found.append(
                    (
                        node.lineno,
                        node.col_offset,
                        alias.asname or alias.name,
                        module,
                    )
                )

    found.sort(key=lambda item: (item[0], item[1]))

    return found


def find_unused_imports_in_source(source, file):
    """Return imports in source whose names appear to be unused.

    Static and conservative. A name counts as used if it appears
    anywhere in the file as a plain name (in any scope), inside a
    string annotation, or in a module-level __all__ list.

    Not reported: star imports, __future__ imports, and anything in
    an __init__.py file (imports there are usually re-exports).

    Limits: a local variable or parameter with the same name as an
    import counts as a use, and names used only dynamically
    (getattr, globals(), eval, strings other than annotations) are
    not seen, so results are candidates, not proof.
    """

    try:
        tree = ast.parse(source, filename=file)
    except SyntaxError as error:
        raise AnalysisError(
            f"Invalid Python syntax: {file}"
        ) from error

    if Path(file).name == "__init__.py":
        return []

    used = _used_names(tree)

    return [
        UnusedImport(name, module, line, file)
        for line, _, name, module in _imports(tree)
        if name not in used
    ]


def find_unused_imports(path):
    """Read a Python file and return its apparently unused imports."""

    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError as error:
        raise FileError(
            f"Unable to read file: {path}"
        ) from error
    except UnicodeError as error:
        raise FileError(
            f"Unable to decode file: {path}"
        ) from error

    return find_unused_imports_in_source(source, str(path))
