import ast
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash"}
SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".ksh"}


@dataclass(frozen=True)
class CommandImport:
    """One module imported by a Python command.

    kind is "stdlib" for the standard library, "found" when the
    module's file was located, and "missing" otherwise. origin is the
    file the module lives in, or None when there is no file (builtin
    or missing modules).
    """

    module: str
    kind: str
    origin: Path | None = None


def _read_start(path, size=256):
    try:
        with Path(path).open("rb") as file:
            return file.read(size)
    except OSError:
        return None


def _interpreter(first_line):
    """Return the interpreter name from a shebang line."""

    tokens = first_line[2:].split()

    if not tokens:
        return ""

    name = Path(tokens[0]).name

    if name == "env":
        for token in tokens[1:]:
            if token.startswith("-") or "=" in token:
                continue

            return Path(token).name

        return ""

    return name


def command_kind(path):
    """Classify source from its contents and established source suffixes.

    Returns "elf", "python", "shell", "perl", "ruby", "javascript", "lua",
    "typescript", "c", "script" (a shebang
    for some other interpreter) or "unknown".
    """

    path = Path(path)
    start = _read_start(path)

    if start is None:
        return "unknown"

    if path.suffix in (".pm", ".pl") and not start.startswith((b"#!", b"\x7fELF")):
        return "perl"

    if path.suffix == ".rb" and not start.startswith((b"#!", b"\x7fELF")):
        return "ruby"

    if path.suffix in {".js", ".mjs", ".cjs"} and not start.startswith((b"#!", b"\x7fELF")):
        return "javascript"

    if path.suffix == ".lua" and not start.startswith((b"#!", b"\x7fELF")):
        return "lua"

    if path.suffix in {".ts", ".tsx", ".mts", ".cts"} and not start.startswith((b"#!", b"\x7fELF")):
        return "typescript"

    if path.suffix in {".c", ".h"} and not start.startswith((b"#!", b"\x7fELF")):
        return "c"

    if start.startswith(b"\x7fELF"):
        return "elf"

    if path.suffix.lower() in SHELL_SUFFIXES:
        return "shell"

    if start.startswith(b"#!"):
        line = start.splitlines()[0].decode("utf-8", errors="replace")
        name = _interpreter(line)

        if name.startswith("python"):
            return "python"

        if name in SHELLS:
            return "shell"

        if name.startswith("perl"):
            return "perl"

        if name.startswith("ruby"):
            return "ruby"

        if name in {"node", "nodejs"}:
            return "javascript"

        if name.startswith(("lua", "luajit")):
            return "lua"

        return _plugin_kind(path) or "script"

    if path.suffix == ".py":
        return "python"

    return _plugin_kind(path) or "unknown"


def _plugin_kind(path):
    from .analyzers import plugin_kind_for

    return plugin_kind_for(path)


def python_imports(path):
    """Return the sorted absolute module names a Python file imports.

    Relative imports are skipped. A file that cannot be read or
    parsed gives an empty tuple.
    """

    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return ()

    modules = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module)

    return tuple(sorted(modules))


def find_module_file(name, search_paths=()):
    """Return the file a module lives in, or None.

    Only the top-level name goes through importlib, which never runs
    package code. Submodules are found by walking the package's
    directories, so nothing is imported or executed.
    """

    top, _, rest = name.partition(".")

    for root in search_paths:
        root = Path(root)
        target = root.joinpath(*name.split("."))
        candidates = (target.with_suffix(".py"), target / "__init__.py")

        for candidate in candidates:
            if candidate.is_file():
                return candidate

    try:
        spec = importlib.util.find_spec(top)
    except (ImportError, ValueError):
        return None

    if spec is None or not spec.has_location or spec.origin is None:
        return None

    origin = Path(spec.origin)

    if not rest:
        return origin

    for base in spec.submodule_search_locations or ():
        target = Path(base).joinpath(*rest.split("."))

        for candidate in (
            target.with_suffix(".py"),
            target / "__init__.py",
        ):
            if candidate.is_file():
                return candidate

    return origin


def resolve_launcher(path):
    """Return a CommandImport for every module a Python command imports.

    Installed commands are often tiny launchers. This shows where the
    real code lives, so it can be read next. Non-Python files give an
    empty tuple.
    """

    if command_kind(path) != "python":
        return ()

    result = []

    for module in python_imports(path):
        top = module.partition(".")[0]

        if top in sys.stdlib_module_names:
            result.append(
                CommandImport(
                    module, "stdlib", find_module_file(module, (Path(path).parent,))
                )
            )
            continue

        origin = find_module_file(module, (Path(path).parent,))
        kind = "found" if origin is not None else "missing"
        result.append(CommandImport(module, kind, origin))

    return tuple(result)


def _file_for(path):
    """Return the module file at path (name.py or a package), or None."""

    for candidate in (
        path.parent / (path.name + ".py"),
        path / "__init__.py",
    ):
        if candidate.is_file():
            return candidate

    return None


def _is_module_named(origin, leaf):
    return origin.name == leaf + ".py" or (
        origin.name == "__init__.py" and origin.parent.name == leaf
    )


def import_files(path):
    """Return the files a Python file's imports lead to.

    See import_file_lines, which also gives the line of each import.
    """

    return list(import_file_lines(path))


def import_file_lines(path):
    """Return {file: line} for the files a Python file's imports lead to.

    line is the first import statement that leads to the file.

    Relative imports are resolved against the file's own directory.
    Absolute imports skip the standard library and modules that cannot
    be found. "from pkg import name" also includes pkg/name when name
    is a module, but not when it is a function or class. Nothing is
    imported or executed. Each file appears once, in a stable order.
    """

    path = Path(path).resolve()

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return {}

    statements = {}

    def note(key, line):
        if key not in statements or line < statements[key]:
            statements[key] = line

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                note((0, alias.name, ()), node.lineno)
        elif isinstance(node, ast.ImportFrom):
            names = tuple(sorted(alias.name for alias in node.names))
            note((node.level, node.module or "", names), node.lineno)

    found = {}

    def add(origin, line):
        origin = origin.resolve()
        if origin not in found or line < found[origin]:
            found[origin] = line

    for (level, module, names), line in sorted(statements.items()):
        if level == 0:
            if not module:
                continue

            if module.partition(".")[0] in sys.stdlib_module_names:
                continue

            origin = find_module_file(module, (path.parent,))

            if origin is not None:
                add(origin, line)

            for name in names:
                if name == "*":
                    continue

                origin = find_module_file(f"{module}.{name}", (path.parent,))

                if origin is not None and _is_module_named(origin, name):
                    add(origin, line)

            continue

        base = path.parent

        for _ in range(level - 1):
            base = base.parent

        if module:
            target = base.joinpath(*module.split("."))
            origin = _file_for(target)
            package = target
        else:
            target = base
            origin = base / "__init__.py"
            package = base

        if origin is not None and origin.is_file():
            add(origin, line)

        for name in names:
            if name == "*":
                continue

            origin = _file_for(package / name)

            if origin is not None:
                add(origin, line)

    return found
