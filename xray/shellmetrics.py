import re
from dataclasses import dataclass
from pathlib import Path

from .errors import FileError
from .shellscan import scan_shell

_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_TOKEN = re.compile(r"(?<![\w.$/-])[A-Za-z_]+(?![\w.-])|&&|\|\||;;")
_FUNCTION = re.compile(
    r"^\s*(?:function\s+)?([A-Za-z_][\w.:-]*)\s*\(\s*\)"
    r"|^\s*function\s+([A-Za-z_][\w.:-]*)"
)

_OPEN = {"if", "for", "while", "until", "case", "select"}
_CLOSE = {"fi", "done", "esac"}
_BRANCH = {"if", "elif", "for", "while", "until", "select", "&&", "||", ";;"}

NOTE = (
    "Note: approximate. Keywords are counted after removing comments, "
    "quoted text and heredocs"
)


@dataclass(frozen=True)
class ShellFunction:
    """One shell function: its first line, line span and metrics."""

    name: str
    line: int
    lines: int
    complexity: int
    nesting: int


@dataclass(frozen=True)
class ShellMetrics:
    """Approximate metrics for a shell script.

    complexity is 1 plus the number of if/elif/for/while/until/select
    keywords, case items (;;), && and ||. nesting is the deepest level
    of if/for/while/until/case/select blocks.
    """

    file: str
    lines_of_code: int
    complexity: int
    nesting: int
    functions: tuple = ()


def _clean(text):
    raw = text.splitlines()
    cleaned = []
    quote = None
    heredoc = None

    for line in raw:
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None

            cleaned.append("")
            continue

        started_in_quote = quote is not None
        out = []
        i = 0

        while i < len(line):
            ch = line[i]

            if quote == "'":
                if ch == "'":
                    quote = None
            elif quote == '"':
                if ch == "\\":
                    i += 1
                elif ch == '"':
                    quote = None
            elif ch == "\\":
                i += 1
            elif ch in "'\"":
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1].isspace()):
                break
            else:
                out.append(ch)

            i += 1

        text_out = "".join(out)

        if not started_in_quote and re.search(r"(?<!<)<<(?!<)", text_out):
            match = _HEREDOC.search(line)

            if match:
                heredoc = match.group(2)

        cleaned.append(text_out)

    return raw, cleaned


def _measure(lines):
    complexity = 1
    depth = 0
    deepest = 0

    for line in lines:
        for match in _TOKEN.finditer(line):
            word = match.group(0)

            if word in _BRANCH:
                complexity += 1

            if word in _OPEN:
                depth += 1
                deepest = max(deepest, depth)
            elif word in _CLOSE:
                depth = max(0, depth - 1)

    return complexity, deepest


def _function_end(cleaned, start):
    """Return the last line of a function body.

    The body is a { } group or, for subshell functions, a ( ) group.
    The first one opened after the "()" of the definition decides.
    """

    header = re.sub(r"\(\s*\)", "", cleaned[start], count=1)
    pair = None
    depth = 0

    for i in range(start, len(cleaned)):
        line = header if i == start else cleaned[i]

        for ch in line:
            if pair is None:
                if ch == "{":
                    pair = ("{", "}")
                elif ch == "(":
                    pair = ("(", ")")
                else:
                    continue

            if ch == pair[0]:
                depth += 1
            elif ch == pair[1]:
                depth -= 1

        if pair is not None and depth <= 0:
            return i

        if pair is None and i > start:
            return start

    return len(cleaned) - 1


def analyze_shell_metrics(path):
    file = str(path)

    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise FileError(f"Unable to read file: {file}") from error
    except UnicodeError as error:
        raise FileError(f"Unable to decode file: {file}") from error

    raw, cleaned = _clean(text)

    code_lines = sum(
        1
        for line in raw
        if line.strip() and not line.strip().startswith("#")
    )

    functions = []

    for index, line in enumerate(cleaned):
        match = _FUNCTION.match(line)

        if not match:
            continue

        end = _function_end(cleaned, index)
        complexity, nesting = _measure(cleaned[index:end + 1])

        functions.append(
            ShellFunction(
                match.group(1) or match.group(2),
                index + 1,
                end - index + 1,
                complexity,
                nesting,
            )
        )

    complexity, nesting = _measure(cleaned)

    return ShellMetrics(
        file,
        code_lines,
        complexity,
        nesting,
        tuple(functions),
    )


def shell_metrics_lines(path):
    metrics = analyze_shell_metrics(path)
    commands = scan_shell(path).commands
    functions = sorted(
        metrics.functions,
        key=lambda item: (-item.complexity, item.name),
    )

    lines = [
        f"Lines of code:      {metrics.lines_of_code}",
        f"Functions:          {len(functions)}",
        f"External commands:  {len(commands)}",
        f"Complexity:         {metrics.complexity}",
        f"Maximum nesting:    {metrics.nesting}",
        "",
        "Functions (most complex first)",
    ]

    if not functions:
        lines.append("- none")

    for item in functions:
        lines.append(
            f"- {item.name}: complexity {item.complexity}, "
            f"nesting {item.nesting}, {item.lines} lines "
            f"(line {item.line})"
        )

    lines.append("")
    lines.append(NOTE)

    return lines
