import ast
from dataclasses import dataclass
from pathlib import Path

from .dependencies import classify_dependency, discover_local_modules
from .errors import AnalysisError, FileError, XRAYError
from .symbols import extract_symbols


@dataclass(frozen=True)
class Reference:
    """A use of an imported name, linked to its definition if possible.

    status is "resolved", "unresolved" or "external".
    target is "relative/path.py:name" when status is "resolved".
    """

    name: str
    line: int
    file: str
    status: str
    target: str | None = None


def _find_module_file(base_dir, module):
    parts = module.split(".") if module else []

    if parts:
        as_module = base_dir.joinpath(
            *parts[:-1],
            parts[-1] + ".py",
        )

        if as_module.is_file():
            return as_module

    as_package = base_dir.joinpath(*parts, "__init__.py")

    if as_package.is_file():
        return as_package

    return None


def _find_symbol(module_file, name):
    try:
        symbols = extract_symbols(module_file)
    except XRAYError:
        return None

    found = None

    for symbol in symbols:
        if symbol.parent is None and symbol.name == name:
            found = symbol

    return found


def _resolve(
    path,
    project_root,
    local_modules,
    module,
    level,
    original,
):
    if level:
        base_dir = path.parent

        for _ in range(level - 1):
            base_dir = base_dir.parent

        module_file = _find_module_file(base_dir, module)

    else:
        kind = classify_dependency(module or "", local_modules)

        if kind != "local":
            return "external", None

        module_file = _find_module_file(project_root, module)

    if module_file is None:
        return "unresolved", None

    symbol = _find_symbol(module_file, original)

    if symbol is None:
        return "unresolved", None

    try:
        location = module_file.relative_to(project_root).as_posix()
    except ValueError:
        location = str(module_file)

    return "resolved", f"{location}:{symbol.name}"


def find_references(path, project_root=None):
    """Return references to names imported with "from X import name".

    Static and conservative: attribute access (module.name), star
    imports and shadowed names are not resolved.
    """

    file = str(path)
    path = Path(path).resolve()

    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError as error:
        raise FileError(
            f"Unable to read file: {file}"
        ) from error
    except UnicodeError as error:
        raise FileError(
            f"Unable to decode file: {file}"
        ) from error

    try:
        tree = ast.parse(source, filename=file)
    except SyntaxError as error:
        raise AnalysisError(
            f"Invalid Python syntax: {file}"
        ) from error

    if project_root is None:
        project_root = path.parent

    project_root = Path(project_root).resolve()
    local_modules = discover_local_modules(project_root)

    imported = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue

                imported[alias.asname or alias.name] = (
                    node.module,
                    node.level,
                    alias.name,
                )

    found = []

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in imported
        ):
            continue

        module, level, original = imported[node.id]

        status, target = _resolve(
            path,
            project_root,
            local_modules,
            module,
            level,
            original,
        )

        found.append(
            (
                node.lineno,
                node.col_offset,
                Reference(
                    node.id,
                    node.lineno,
                    file,
                    status,
                    target,
                ),
            )
        )

    found.sort(key=lambda item: (item[0], item[1]))

    return [reference for _, _, reference in found]
