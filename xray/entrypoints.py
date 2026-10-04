import ast
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash"}


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
    """Classify a file from its contents, not its extension.

    Returns "elf", "python", "shell", "perl", "script" (a shebang
    for some other interpreter) or "unknown".
    """

    path = Path(path)
    start = _read_start(path)

    if start is None:
        return "unknown"

    if start.startswith(b"\x7fELF"):
        return "elf"

    if start.startswith(b"#!"):
        line = start.splitlines()[0].decode("utf-8", errors="replace")
        name = _interpreter(line)

        if name.startswith("python"):
            return "python"

        if name in SHELLS:
            return "shell"

        if name.startswith("perl"):
            return "perl"

        return "script"

    if path.suffix == ".py":
        return "python"

    return "unknown"


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
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                modules.add(node.module)

    return tuple(sorted(modules))


def find_module_file(name):
    """Return the file a module lives in, or None.

    Only the top-level name goes through importlib, which never runs
    package code. Submodules are found by walking the package's
    directories, so nothing is imported or executed.
    """

    top, _, rest = name.partition(".")

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
                CommandImport(module, "stdlib", find_module_file(module))
            )
            continue

        origin = find_module_file(module)
        kind = "found" if origin is not None else "missing"
        result.append(CommandImport(module, kind, origin))

    return tuple(result)
