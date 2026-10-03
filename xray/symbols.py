import ast
from dataclasses import dataclass, field

from .errors import AnalysisError, FileError


SYMBOL_KINDS = (
    "function",
    "class",
    "method",
    "variable",
)


@dataclass(frozen=True)
class Symbol:
    """A named definition found inside a source file."""

    name: str
    kind: str
    file: str
    line: int
    parent: str | None = None
    metadata: dict = field(
        default_factory=dict,
        compare=False,
        hash=False,
    )

    def __post_init__(self):
        if self.kind not in SYMBOL_KINDS:
            raise ValueError(
                f"Unknown symbol kind: {self.kind}"
            )

    @property
    def qualified_name(self):
        if self.parent:
            return f"{self.parent}.{self.name}"

        return self.name


def _collect(body, file, parent, symbols):
    for node in body:
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            metadata = {}

            if isinstance(node, ast.AsyncFunctionDef):
                metadata["async"] = True

            symbols.append(
                Symbol(
                    node.name,
                    "method" if parent else "function",
                    file,
                    node.lineno,
                    parent,
                    metadata,
                )
            )

        elif isinstance(node, ast.ClassDef):
            symbols.append(
                Symbol(
                    node.name,
                    "class",
                    file,
                    node.lineno,
                    parent,
                )
            )

            child_parent = (
                f"{parent}.{node.name}"
                if parent
                else node.name
            )

            _collect(node.body, file, child_parent, symbols)

        elif parent is None and isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    symbols.append(
                        Symbol(
                            target.id,
                            "variable",
                            file,
                            target.lineno,
                        )
                    )

        elif parent is None and isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.value is not None
            ):
                symbols.append(
                    Symbol(
                        node.target.id,
                        "variable",
                        file,
                        node.target.lineno,
                    )
                )


def extract_symbols_from_source(source, file):
    """Return the module-level symbols defined in source."""

    try:
        tree = ast.parse(source, filename=file)
    except SyntaxError as error:
        raise AnalysisError(
            f"Invalid Python syntax: {file}"
        ) from error

    symbols = []
    _collect(tree.body, file, None, symbols)

    return symbols


def extract_symbols(path):
    """Read a Python file and return its symbols."""

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

    return extract_symbols_from_source(source, str(path))
