import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

BUILTINS = frozenset(
    [".", ":", "[", "[[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command", "compgen", "complete", "continue", "declare", "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read", "readarray", "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test", "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset", "wait"]
)

# Words that can come before the real command on the same segment.
PREFIXES = frozenset(
    ["if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "exec", "command", "nohup"]
)

# Commands that run another command given later on the same line, with
# the options of each that take a separate value.
WRAPPERS = {
    "sudo": frozenset(["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"]),
    "doas": frozenset(["-u", "-C"]),
    "env": frozenset(["-u", "-C", "-S", "--unset", "--chdir"]),
    "nice": frozenset(["-n", "--adjustment"]),
    "ionice": frozenset(["-c", "-n", "-p", "-P", "-u"]),
    "stdbuf": frozenset(["-i", "-o", "-e"]),
    "timeout": frozenset(["-k", "-s", "--kill-after", "--signal"]),
    "xargs": frozenset(["-a", "-d", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-s", "--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-lines", "--max-chars", "--replace"]),
}
FIND_ACTIONS = frozenset(["-exec", "-execdir", "-ok", "-okdir"])

# Segments that start with these hold no command to report.
SKIP_SEGMENT = frozenset(
    ["case", "for", "select", "esac", "fi", "done", "in", "function", "coproc"]
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
_DYNAMIC = re.compile(
    r"^[\"']?\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?]|\{[A-Za-z_][A-Za-z0-9_]*[^}]*\})[\"']?$"
)
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


def _legacy_function_lines(path):
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

        if text.startswith("$(", i) or (
            quote is None and text.startswith(("<(", ">("), i)
        ):
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

    if first == "eval" and index + 1 < len(words) and not any(
        "$" in word or "`" in word for word in words[index + 1:]
    ):
        # A literal eval string is ordinary shell code: read it.
        _collect(" ".join(words[index + 1:]), commands, sources, dynamic)
        return

    # "_" is _extract's placeholder for a command substitution: in command
    # position it runs whatever the substitution prints.
    if first == "_" or (dynamic is not None and (first == "eval" or _DYNAMIC.match(first))):
        if dynamic is not None:
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

    rest = words[index + 1:]

    if first == "find":
        for position, word in enumerate(rest):
            if word in FIND_ACTIONS:
                _scan_words(rest[position + 1:], commands, sources, dynamic)
        return

    if first in WRAPPERS:
        _scan_words(_wrapped(first, rest), commands, sources, dynamic)


def _wrapped(wrapper, words):
    """Return the words of the command a wrapper runs."""

    takes_value = WRAPPERS[wrapper]
    index = 0

    while index < len(words):
        word = words[index]

        if word == "--":
            return words[index + 1:]

        if wrapper == "env" and _ASSIGN.match(word):
            index += 1
            continue

        if not word.startswith("-") or word == "-":
            break

        index += 2 if word in takes_value else 1

    if wrapper == "timeout" and index < len(words):
        index += 1  # the duration

    return words[index:]


def _collect(text, commands, sources, dynamic=None):
    outer, inners = _extract(text)

    for inner in inners:
        _collect(inner, commands, sources, dynamic)

    for segment in _segments(outer):
        words = _words(segment)

        if words:
            _scan_words(words, commands, sources, dynamic)


def _legacy_scan_shell(path):
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


def _legacy_command_lines(path):
    """Return {name: line} for the first line each command or source appears on.

    Each logical line (backslash continuations joined, here-documents
    skipped) is read on its own with the same rules as scan_shell. A
    command that only shows up when lines are read together, such as
    one inside a multi-line subshell, falls back to the first
    non-comment line holding the word. Names never found have no entry.
    """

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    numbered = _numbered_lines(text)
    found = {}
    logical = []
    start = None

    for number, line in numbered:
        if start is None:
            start = number
        if line.endswith("\\"):
            logical.append(line[:-1])
            continue
        logical.append(line)
        joined = " ".join(logical)
        logical = []
        stripped = joined.lstrip()
        if stripped and not stripped.startswith("#"):
            commands, sources = set(), set()
            try:
                _collect(_CASE_PATTERN.sub("", joined, count=1), commands, sources, [])
            except (ValueError, IndexError):
                commands = sources = set()
            for name in commands | sources:
                found.setdefault(name, start)
        start = None

    scan = _legacy_scan_shell(path)
    for name in (*scan.commands, *scan.sources):
        if name in found:
            continue
        word = re.compile(r"(?<![\w./-])" + re.escape(name) + r"(?![\w.-])")
        for number, line in numbered:
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if word.search(line):
                found[name] = number
                break

    return found


def _legacy_changes_path(path):
    """Return True when a shell script assigns PATH, so lookups made now may differ."""

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    return re.search(r"(?m)^\s*(?:export\s+)?PATH\+?=", text) is not None


# -- parser-based reading ------------------------------------------------------

# Shells whose -c argument is shell code XRAY can read.
SHELLS = frozenset(["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox"])
# Extra wrappers: commands that run the command named after their options.
WRAPPERS.update({
    "setsid": frozenset(),
    "nohup": frozenset(),
    "runuser": frozenset(["-u", "-g", "-G", "--user", "--group"]),
    "chrt": frozenset(),
    "taskset": frozenset(),
})


@dataclass(frozen=True)
class ShellFacts:
    """Everything the parser learned about a script, with line numbers.

    commands and sources map each name to the sorted lines it appears on;
    via maps a command name to how it was reached when that was not a
    plain command line ("eval", "sh -c", "trap", a wrapper or "find
    -exec"); dynamic lists (line, word) for each command whose name is
    only known at run time; path_lines are the lines that assign PATH.
    """

    functions: dict = field(default_factory=dict)
    commands: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    via: dict = field(default_factory=dict)
    dynamic: tuple = ()
    path_lines: tuple = ()


_VARREF = re.compile(r'^("?)\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:\[(?:@|\*|0)\])?\}|([A-Za-z_][A-Za-z0-9_]*))\1$')


def _variable_commands(raw, assignments):
    """Word lists a command written as $NAME may run, or None if unknown.

    Only variables the script assigns, every time, to a fixed value are
    resolved: the result is a guess, since the environment or a sourced
    file could still set the variable before it is used.
    """

    from .shparse import Word

    match = _VARREF.match(raw)
    if not match:
        return None
    name = match.group(2) or match.group(3)
    values = assignments.get(name)
    if not values or any(value is None for value in values):
        return None
    options = []
    for value in values:
        if isinstance(value, tuple):
            if not value or not value[0].static:
                return None
            option = list(value)
        elif not value.strip():
            return None
        elif match.group(1):
            if any(ch.isspace() for ch in value):
                return None
            option = [Word(value, True, value)]
        else:
            option = [Word(part, True, part) for part in value.split()]
        if option not in options:
            options.append(option)
    return name, options


class _Reader:
    def __init__(self, assignments=None):
        self.commands = {}
        self.sources = {}
        self.via = {}
        self.plain = set()
        self.dynamic = []
        self.assignments = assignments or {}

    def add(self, table, name, line, via=None):
        table.setdefault(name, set()).add(line)
        if table is not self.commands:
            return
        if via is None:
            self.plain.add(name)
            self.via.pop(name, None)
        elif name not in self.plain:
            self.via.setdefault(name, via)

    def code(self, text, line, via, result):
        from .shparse import parse

        before = len(result.commands)
        parse(text, base_line=line, result=result)
        for command in result.commands[before:]:
            self.words(list(command.words), line, via)
        del result.commands[before:]

    def words(self, words, line, via=None, result=None):
        from .shparse import ParseResult

        index = 0
        while index < len(words) and words[index].static and words[index].value in ("exec", "command", "nohup", "time", "!"):
            prefix = words[index].value
            index += 1
            if prefix == "command":
                if index < len(words) and words[index].value in ("-v", "-V"):
                    return  # a lookup, nothing runs
                while index < len(words) and words[index].value == "-p":
                    index += 1
            if prefix == "exec":
                while index < len(words) and words[index].value.startswith("-"):
                    index += 2 if words[index].value == "-a" else 1
        if index >= len(words):
            return
        first = words[index]
        rest = words[index + 1:]
        if not first.static:
            resolved = _variable_commands(first.raw, self.assignments)
            if resolved is None:
                self.dynamic.append((line, first.raw))
                return
            variable, options = resolved
            for option in options:
                self.words([*option, *rest], line, f"${variable}")
            return
        name = first.value
        if name in ("source", "."):
            if rest:
                self.add(self.sources, rest[0].value, line)
            return
        if name == "eval":
            if rest and all(word.static for word in rest):
                self.code(" ".join(word.value for word in rest), line, "eval", ParseResult())
            else:
                self.dynamic.append((line, "eval"))
            return
        if name == "trap":
            if rest and rest[0].static and rest[0].value not in ("-", "") and not rest[0].value.startswith("-"):
                self.code(rest[0].value, line, "trap", ParseResult())
            return
        if name in BUILTINS:
            return
        if not (_NAME.match(name) and not name.isdigit()):
            return
        self.add(self.commands, name, line, via)

        values = [word.value for word in rest]
        if Path(name).name in SHELLS:
            for position, value in enumerate(values):
                if value.startswith("-") and not value.startswith("--") and "c" in value[1:]:
                    if position + 1 < len(rest) and rest[position + 1].static:
                        self.code(rest[position + 1].value, line, f"{Path(name).name} -c", ParseResult())
                    elif position + 1 < len(rest):
                        self.dynamic.append((line, f"{Path(name).name} -c {rest[position + 1].raw}"))
                    return
            return
        if name == "su":
            for position, value in enumerate(values[:-1]):
                if value in ("-c", "--command") and rest[position + 1].static:
                    self.code(rest[position + 1].value, line, "su -c", ParseResult())
            return
        if name == "find":
            for position, value in enumerate(values):
                if value in FIND_ACTIONS:
                    self.words(rest[position + 1:], line, "find " + value)
            return
        if name in WRAPPERS:
            wrapped = _wrapped(name, values)
            self.words(rest[len(rest) - len(wrapped):], line, name)


def shell_facts(path):
    """Return ShellFacts for a shell script, read with the full parser.

    A file that cannot be read gives empty ShellFacts.
    """

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ShellFacts()
    return facts_of_text(text)


def facts_of_text(text):
    from .shparse import parse

    result = parse(text)
    reader = _Reader(result.assignments)
    for command in result.commands:
        reader.words(list(command.words), command.line)
    functions = dict(result.functions)
    for name in functions:
        reader.commands.pop(name, None)
        reader.via.pop(name, None)
    return ShellFacts(
        functions=functions,
        commands={name: sorted(lines) for name, lines in sorted(reader.commands.items())},
        sources={name: sorted(lines) for name, lines in sorted(reader.sources.items())},
        via=reader.via,
        dynamic=tuple(sorted(reader.dynamic)),
        path_lines=tuple(sorted(set(result.path_lines))),
    )


def _facts_or_none(path):
    try:
        return shell_facts(path)
    except (RecursionError, ValueError, IndexError, AttributeError):
        return None


def scan_shell(path):
    """Return a ShellScan for a shell script.

    A file that cannot be read gives an empty ShellScan.
    """

    facts = _facts_or_none(path)
    if facts is None:
        return _legacy_scan_shell(path)
    return ShellScan(
        tuple(sorted(facts.functions)),
        tuple(facts.sources),
        tuple(facts.commands),
        len(facts.dynamic),
    )


def function_lines(path):
    """Return {function name: line number} where each definition starts."""

    facts = _facts_or_none(path)
    if facts is None:
        return _legacy_function_lines(path)
    return dict(facts.functions)


def command_lines(path):
    """Return {name: line} for the first line each command or source appears on."""

    facts = _facts_or_none(path)
    if facts is None:
        return _legacy_command_lines(path)
    found = {name: lines[0] for name, lines in facts.sources.items()}
    found.update({name: lines[0] for name, lines in facts.commands.items()})
    return found


def changes_path(path):
    """Return True when a shell script assigns PATH, so lookups made now may differ."""

    facts = _facts_or_none(path)
    if facts is None:
        return _legacy_changes_path(path)
    return bool(facts.path_lines)
