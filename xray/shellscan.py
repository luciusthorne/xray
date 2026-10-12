import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

BUILTINS = frozenset(
    ". : [ [[ alias bg bind break builtin caller cd command compgen "
    "complete continue declare dirs disown echo enable eval exec exit "
    "export false fg getopts hash help history jobs kill let local "
    "logout mapfile popd printf pushd pwd read readarray readonly "
    "return set shift shopt source suspend test times trap true type "
    "typeset ulimit umask unalias unset wait".split()
)

# Words that can come before the real command on the same segment.
PREFIXES = frozenset(
    "if then else elif do while until ! { } time exec command nohup".split()
)

# Segments that start with these hold no command to report.
SKIP_SEGMENT = frozenset(
    "case for select esac fi done in function coproc".split()
)

_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_CASE_PATTERN = re.compile(
    r"^\s*(?:\(?[^\s()=;|&'\"]+(?:\|[^\s()=;|&'\"]+)*"
    r"|[^\s()=;|&'\"]+(?:\s+\|\s+[^\s()=;|&'\"]+)+)\)"
)
_FUNCTION = re.compile(
    r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_.:-]*)\s*\(\s*\)"
    r"|^\s*function\s+([A-Za-z_][A-Za-z0-9_.:-]*)",
    re.MULTILINE,
)
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
_NAME = re.compile(r"^[A-Za-z0-9_./][A-Za-z0-9_./+@:-]*$")


@dataclass(frozen=True)
class ShellScan:
    """What a shell script defines, loads and runs.

    functions are the functions the script defines, sources the files
    it loads with "source" or ".", and commands the external commands
    it invokes. Each is sorted and holds every name once. This is a
    static, line-based reading: eval, commands built from variables
    and quotes that span many lines are not understood.
    """

    functions: tuple = ()
    sources: tuple = ()
    commands: tuple = ()
    dynamic: int = field(default=0, compare=False)


def _numbered_lines(text):
    kept = []
    delimiter = None

    for number, line in enumerate(text.splitlines(), 1):
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None

            continue

        kept.append((number, line))

        if "((" in line:
            continue

        match = _HEREDOC.search(line)

        if match:
            delimiter = match.group(2)

    return kept


def _strip_heredocs(text):
    return [line for _, line in _numbered_lines(text)]


def function_lines(path):
    """Return {function name: line number} in the original file.

    Uses the same heredoc and continuation handling as scan_shell,
    but reports the line where each definition starts. A file that
    cannot be read gives an empty dict.
    """

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    logical = []

    for number, line in _numbered_lines(text):
        if logical and logical[-1][1].endswith("\\"):
            start, joined = logical[-1]
            logical[-1] = (start, joined[:-1] + " " + line)
        else:
            logical.append((number, line))

    found = {}

    for number, line in logical:
        match = _FUNCTION.search(line)

        if match:
            found.setdefault(match.group(1) or match.group(2), number)

    return found


def _matching(text, start):
    """Return the index of the parenthesis that closes text[start]."""

    depth = 0

    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1

            if depth == 0:
                return index

    return len(text)


def _extract(text):
    """Return (outer, inners).

    outer is the text without comments, with every command
    substitution and arithmetic expression replaced by a placeholder.
    inners holds the text of each substitution.
    """

    out = []
    inners = []
    quote = None
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]

        if quote == "'":
            out.append(ch)

            if ch == "'":
                quote = None

            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue

        if (
            ch == "#"
            and quote is None
            and (i == 0 or text[i - 1] in " \t\n;&|(")
        ):
            while i < n and text[i] != "\n":
                i += 1

            continue

        if ch == "`":
            end = text.find("`", i + 1)

            if end == -1:
                end = n

            inners.append(text[i + 1:end])
            out.append("_")
            i = end + 1
            continue

        if text.startswith("$((", i):
            out.append("0")
            i = _matching(text, i + 1) + 1
            continue

        if text.startswith("((", i) and quote is None:
            out.append("0")
            i = _matching(text, i) + 1
            continue

        if text.startswith("$(", i):
            end = _matching(text, i + 1)
            inners.append(text[i + 2:end])
            out.append("_")
            i = end + 1
            continue

        if ch == '"':
            quote = None if quote == '"' else '"'
        elif ch == "'" and quote is None:
            quote = "'"

        out.append(ch)
        i += 1

    return "".join(out), inners


def _is_redirect_ampersand(text, index):
    previous = text[index - 1] if index > 0 else ""
    following = text[index + 1] if index + 1 < len(text) else ""

    return previous in "<>" or following == ">"


def _segments(outer):
    """Split text into command segments at separators outside quotes."""

    segments = []
    current = []
    quote = None
    i = 0
    n = len(outer)

    while i < n:
        ch = outer[i]

        if quote:
            current.append(ch)

            if ch == "\\" and quote == '"' and i + 1 < n:
                current.append(outer[i + 1])
                i += 2
                continue

            if ch == quote:
                quote = None

            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            current.append(outer[i:i + 2])
            i += 2
            continue

        if ch in "'\"":
            quote = ch
            current.append(ch)
            i += 1
            continue

        if ch in ";\n|()" or (
            ch == "&" and not _is_redirect_ampersand(outer, i)
        ):
            segments.append("".join(current))
            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    segments.append("".join(current))

    return segments


def _words(segment):
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _scan_words(words, commands, sources, dynamic=None):
    index = 0

    while index < len(words) and (
        words[index] in PREFIXES or _ASSIGN.match(words[index])
    ):
        index += 1

    if index >= len(words):
        return

    first = words[index]

    if first in SKIP_SEGMENT:
        return

    if dynamic is not None and (first == "eval" or first.startswith("$")):
        dynamic.append(first)
        return

    if first in ("source", "."):
        if index + 1 < len(words):
            sources.add(words[index + 1])

        return

    if first in BUILTINS:
        return

    if _NAME.match(first) and not first.isdigit():
        commands.add(first)


def _collect(text, commands, sources, dynamic=None):
    outer, inners = _extract(text)

    for inner in inners:
        _collect(inner, commands, sources, dynamic)

    for segment in _segments(outer):
        words = _words(segment)

        if words:
            _scan_words(words, commands, sources, dynamic)


def scan_shell(path):
    """Return a ShellScan for a shell script.

    A file that cannot be read gives an empty ShellScan.
    """

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ShellScan()

    joined = "\n".join(_strip_heredocs(text)).replace("\\\n", " ")

    functions = set()

    for match in _FUNCTION.finditer(joined):
        functions.add(match.group(1) or match.group(2))

    cleaned = "\n".join(
        _CASE_PATTERN.sub("", line, count=1)
        for line in joined.split("\n")
    )

    commands = set()
    sources = set()
    dynamic = []

    _collect(cleaned, commands, sources, dynamic)

    commands -= functions

    return ShellScan(
        tuple(sorted(functions)),
        tuple(sorted(sources)),
        tuple(sorted(commands)),
        len(dynamic),
    )
