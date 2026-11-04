import ast
from dataclasses import dataclass
from pathlib import Path

from .errors import AnalysisError, FileError, XRAYError

_TRY_NODES = tuple(
    node
    for node in (ast.Try, getattr(ast, "TryStar", None))
    if node is not None
)

_LOOP_NODES = (ast.For, ast.AsyncFor, ast.While)
_WITH_NODES = (ast.With, ast.AsyncWith)
_DEFINITION_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
)


@dataclass(frozen=True)
class FunctionMetrics:
    """Metrics for one function or method.

    name is qualified ("User.save"). lines is the span of the
    definition, from the "def" line to its last line.
    """

    name: str
    file: str
    line: int
    lines: int
    complexity: int
    nesting: int

    @property
    def branches(self):
        return self.complexity - 1


@dataclass(frozen=True)
class FileMetrics:
    """Metrics for one Python file.

    lines_of_code counts non-blank lines that are not comments.
    function_count includes methods.
    """

    file: str
    lines_of_code: int
    class_count: int
    functions: tuple = ()

    @property
    def function_count(self):
        return len(self.functions)

    @property
    def max_complexity(self):
        return max(
            (function.complexity for function in self.functions),
            default=0,
        )

    @property
    def max_nesting(self):
        return max(
            (function.nesting for function in self.functions),
            default=0,
        )


@dataclass(frozen=True)
class ProjectMetrics:
    """Metrics for every Python file under a folder.

    skipped lists files that could not be read or parsed. They are
    not counted in any total.
    """

    files: tuple = ()
    skipped: tuple = ()

    @property
    def python_files(self):
        return len(self.files)

    @property
    def function_count(self):
        return sum(item.function_count for item in self.files)

    @property
    def class_count(self):
        return sum(item.class_count for item in self.files)

    @property
    def lines_of_code(self):
        return sum(item.lines_of_code for item in self.files)

    @property
    def max_complexity(self):
        return max(
            (item.max_complexity for item in self.files),
            default=0,
        )

    @property
    def max_nesting(self):
        return max(
            (item.max_nesting for item in self.files),
            default=0,
        )

    def most_complex(self, limit=10):
        """Return the most complex functions, worst first."""

        functions = [
            function
            for item in self.files
            for function in item.functions
        ]

        functions.sort(
            key=lambda function: (
                -function.complexity,
                function.file,
                function.line,
            )
        )

        return functions[:limit]


def _is_irrefutable(case):
    return (
        case.guard is None
        and isinstance(case.pattern, ast.MatchAs)
        and case.pattern.pattern is None
    )


def _complexity(function):
    total = 1

    for statement in function.body:
        for node in ast.walk(statement):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.IfExp,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.ExceptHandler,
                ),
            ):
                total += 1

            elif isinstance(node, ast.BoolOp):
                total += len(node.values) - 1

            elif isinstance(node, ast.comprehension):
                total += 1 + len(node.ifs)

            elif isinstance(node, ast.match_case) and not _is_irrefutable(node):
                total += 1

    return total


def _nesting(body, depth):
    deepest = depth

    for statement in body:
        deepest = max(deepest, _statement_depth(statement, depth))

    return deepest


def _statement_depth(statement, depth):
    inner = depth + 1

    if isinstance(statement, ast.If):
        deepest = _nesting(statement.body, inner)
        orelse = statement.orelse

        if len(orelse) == 1 and isinstance(orelse[0], ast.If):
            return max(deepest, _statement_depth(orelse[0], depth))

        return max(deepest, _nesting(orelse, inner))

    if isinstance(statement, _LOOP_NODES):
        return max(
            _nesting(statement.body, inner),
            _nesting(statement.orelse, inner),
        )

    if isinstance(statement, _WITH_NODES):
        return _nesting(statement.body, inner)

    if isinstance(statement, _TRY_NODES):
        deepest = max(
            _nesting(statement.body, inner),
            _nesting(statement.orelse, inner),
            _nesting(statement.finalbody, inner),
        )

        for handler in statement.handlers:
            deepest = max(deepest, _nesting(handler.body, inner))

        return deepest

    if isinstance(statement, ast.Match):
        deepest = inner

        for case in statement.cases:
            deepest = max(deepest, _nesting(case.body, inner))

        return deepest

    if isinstance(statement, _DEFINITION_NODES):
        return _nesting(statement.body, depth)

    return depth


def _collect(body, file, parent, functions, classes):
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = f"{parent}.{node.name}" if parent else node.name

            functions.append(
                FunctionMetrics(
                    name,
                    file,
                    node.lineno,
                    node.end_lineno - node.lineno + 1,
                    _complexity(node),
                    _nesting(node.body, 0),
                )
            )

        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)

            qualified = (
                f"{parent}.{node.name}" if parent else node.name
            )

            _collect(node.body, file, qualified, functions, classes)


def _lines_of_code(source):
    return sum(
        1
        for line in source.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def analyze_complexity_source(source, file):
    """Return FileMetrics for Python source.

    Cyclomatic complexity starts at 1 and adds 1 for each if, elif,
    conditional expression, for, async for, while, except handler,
    comprehension generator and comprehension condition, each extra
    operand of "and" / "or", and each non-wildcard match case.
    try, finally, with and assert add nothing.

    Nesting depth is the deepest level of nested control structures
    (if, for, while, with, try, match) inside the function. An
    elif stays on the level of its if. Nested functions and lambdas
    are part of the function that contains them.

    Only module-level functions and methods are measured. Functions
    defined inside module-level if/try blocks are not included, and
    module-level code is not measured.
    """

    try:
        tree = ast.parse(source, filename=file)
    except SyntaxError as error:
        raise AnalysisError(
            f"Invalid Python syntax: {file}"
        ) from error

    functions = []
    classes = []

    _collect(tree.body, file, None, functions, classes)

    return FileMetrics(
        file,
        _lines_of_code(source),
        len(classes),
        tuple(functions),
    )


def _read_source(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as error:
        raise FileError(
            f"Unable to read file: {path}"
        ) from error
    except UnicodeError as error:
        raise FileError(
            f"Unable to decode file: {path}"
        ) from error


def analyze_complexity(path):
    """Read a Python file and return its FileMetrics."""

    return analyze_complexity_source(_read_source(path), str(path))


def analyze_project_complexity(project_root):
    """Return ProjectMetrics for every .py file under project_root.

    File names are relative to project_root. Files that cannot be
    read or parsed are listed in skipped.
    """

    project_root = Path(project_root).resolve()

    files = []
    skipped = []

    for path in sorted(project_root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue

        relative = path.relative_to(project_root).as_posix()

        try:
            files.append(
                analyze_complexity_source(
                    _read_source(path),
                    relative,
                )
            )
        except XRAYError:
            skipped.append(relative)

    return ProjectMetrics(tuple(files), tuple(skipped))
