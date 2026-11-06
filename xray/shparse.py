"""A shell parser that finds the simple commands a script contains.

It reads POSIX sh and the bash extensions scripts use in practice:
quoting ('', "", $'', $""), every expansion form (${...}, $(...),
`...`, $((...)), process substitution), here-documents (unquoted bodies
are scanned for command substitutions), compound commands (if, while,
until, for, select, case, { }, ( ), [[ ]], (( ))), function definitions,
array assignments and every redirection form.

It does not build a full syntax tree. It produces what a reader of
"what does this script run?" needs: each simple command with its words
and the line it starts on, the functions the script defines, and the
lines that assign PATH. Every expansion is kept as written, and a word
is "static" only when its value is known without running anything.

The parser never raises on bad input: unbalanced quotes or brackets run
to the end of the text, the way the shell would report a syntax error.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field

_META = frozenset(" \t\r\n;&|()<>")
_NAME_START = re.compile(r"[A-Za-z_]")
_PARAM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ARRAY_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=$")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?=")
_REDIRECT = re.compile(r"(\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?(&>>|&>|<<<|<<-|<<|<>|<&|>&|>>|>\||<|>)")
_ESAC = re.compile(r"esac(?=[\s;&|)]|$)")

# Reserved words after which another command starts.
_LEADING = frozenset(["if", "then", "else", "elif", "do", "while", "until", "!", "{", "time", "coproc"])
# Reserved words that end a compound command.
_CLOSING = frozenset(["fi", "done", "}", "esac"])

_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
         "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


@dataclass(frozen=True)
class Word:
    """One shell word: its value with quotes removed, expansions kept as written."""

    value: str
    static: bool
    raw: str = ""
    items: tuple = ()  # the element words of an array assignment


@dataclass(frozen=True)
class SimpleCommand:
    """A simple command: its words after any assignments, and its first line."""

    words: tuple
    line: int
    assignments: tuple = ()
    function: str | None = None  # the function whose body holds the command


@dataclass
class ParseResult:
    commands: list = field(default_factory=list)
    functions: dict = field(default_factory=dict)
    path_lines: list = field(default_factory=list)
    # variable name -> list of assigned values: a str for a static scalar,
    # a tuple of Words for an array, None when the value is not static
    assignments: dict = field(default_factory=dict)
    # every assignment, for data flow: (variable, Word, line, function)
    assignment_sites: list = field(default_factory=list)
    # for/select loops: (variable, item Words, line, function)
    loops: list = field(default_factory=list)


class _Parser:
    def __init__(self, text, base_line=1, result=None):
        self.s = text
        self.n = len(text)
        self.i = 0
        self.base_line = base_line
        self.result = result if result is not None else ParseResult()
        self.heredocs = []
        self._newlines = [index for index, ch in enumerate(text) if ch == "\n"]
        self.pending_function = None
        self.braces = []  # one entry per open { group: the function it is the body of, or None
        self.subshell_function = None

    def current_function(self):
        for name in reversed(self.braces):
            if name is not None:
                return name
        return self.subshell_function

    # -- positions ---------------------------------------------------------
    def line_at(self, pos):
        return self.base_line + bisect_right(self._newlines, pos - 1)

    def peek(self, offset=0):
        index = self.i + offset
        return self.s[index] if index < self.n else ""

    def startswith(self, text):
        return self.s.startswith(text, self.i)

    def skip_blanks(self):
        while self.i < self.n:
            ch = self.s[self.i]
            if ch in " \t\r":
                self.i += 1
            elif ch == "\\" and self.peek(1) == "\n":
                self.i += 2
            else:
                return

    def skip_comment(self):
        end = self.s.find("\n", self.i)
        self.i = self.n if end == -1 else end

    # -- command lists -----------------------------------------------------
    def parse_list(self, close=None):
        """Parse commands until the closing parenthesis (consumed) or the end."""

        command_position = True
        cases = []
        while self.i < self.n:
            start = self.i
            self.skip_blanks()
            if self.i >= self.n:
                return
            ch = self.s[self.i]
            if ch == "#":
                self.skip_comment()
                continue
            if ch == "\n":
                self.i += 1
                self.read_heredocs()
                command_position = True
                continue
            if cases and cases[-1] == "pattern":
                self.case_pattern(cases)
                command_position = cases[-1] == "body" if cases else False
                continue
            if ch == ")":
                self.i += 1
                if close == ")":
                    return
                command_position = False
                continue
            if self.startswith((";;&", ";;", ";&")):
                self.i += 3 if self.startswith(";;&") else 2
                if cases:
                    cases[-1] = "pattern"
                command_position = True
                continue
            if self.redirect_at():
                self.read_redirect()
                continue
            if ch in ";&|":
                self.i += 2 if self.s[self.i:self.i + 2] in ("&&", "||", "|&") else 1
                command_position = True
                continue
            if ch == "(":
                if command_position and self.startswith("(("):
                    self.skip_arith()
                else:
                    self.i += 1
                    outer, pending = self.subshell_function, self.pending_function
                    if pending is not None:
                        self.subshell_function, self.pending_function = pending, None
                    self.parse_list(close=")")
                    self.subshell_function = outer
                command_position = False
                continue
            if command_position:
                command_position = self.command(cases)
            elif self.read_word() is None:
                self.i += 1
            if self.i == start:
                self.i += 1

    def case_pattern(self, cases):
        match = _ESAC.match(self.s, self.i)
        if match:
            self.i = match.end()
            cases.pop()
            return
        if self.peek() == "(":
            self.i += 1
        depth = 0
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "\\":
                self.i += 2
            elif ch in "'\"$`":
                self.read_word_part(ch, [])
            elif ch == "(":
                depth += 1
                self.i += 1
            elif ch == ")":
                self.i += 1
                if depth == 0:
                    break
                depth -= 1
            else:
                self.i += 1
        cases[-1] = "body"

    def command(self, cases):
        """Parse one command in command position; return the next command_position."""

        line = self.line_at(self.i)
        word = self.read_word()
        if word is None:
            self.i += 1
            return True
        reserved = word.value if word.static and word.raw == word.value else None

        if reserved == "{":
            self.braces.append(self.pending_function)
            self.pending_function = None
            return True
        if reserved == "}" and self.braces:
            self.braces.pop()
            return False
        if reserved in _LEADING:
            if reserved in ("time", "!"):
                self.skip_blanks()
                if reserved == "time" and self.startswith("-p") and self.peek(2) in " \t":
                    self.i += 2
            return True
        if reserved in _CLOSING:
            if reserved == "esac" and cases:
                cases.pop()
            return False
        if reserved == "case":
            self.skip_blanks()
            self.read_word()
            self.skip_space_and_newlines()
            self.read_word()  # "in"
            cases.append("pattern")
            return False
        if reserved in ("for", "select"):
            self.skip_blanks()
            if self.startswith("(("):
                self.skip_arith()
                return False
            variable = self.read_word()
            items, seen_in = [], False
            try:
                while True:
                    self.skip_blanks()
                    if self.i >= self.n or self.s[self.i] in ";\n&|#":
                        return False
                    item = self.read_word()
                    if item is None:
                        self.i += 1
                    elif item.static and item.value == "do":
                        return True
                    elif item.static and item.value == "in" and not seen_in:
                        seen_in = True
                    else:
                        items.append(item)
            finally:
                if variable is not None:
                    # "for x; do" iterates over the positional parameters
                    words = tuple(items) if seen_in else (Word('"$@"', False, '"$@"'),)
                    self.result.loops.append((variable.value, words, line, self.current_function()))
        if reserved == "function":
            self.skip_blanks()
            name = self.read_word()
            if name is not None:
                self.result.functions.setdefault(name.value, line)
                self.pending_function = name.value
            self.skip_blanks()
            if self.startswith("("):
                self.skip_empty_parens()
            return True
        if reserved == "[[":
            self.read_test()
            return False

        if word.static and self.function_parens():
            self.result.functions.setdefault(word.value, line)
            self.pending_function = word.value
            return True
        self.simple_command(word, line)
        return False

    def skip_space_and_newlines(self):
        while True:
            self.skip_blanks()
            if self.peek() == "\n":
                self.i += 1
                self.read_heredocs()
            elif self.peek() == "#":
                self.skip_comment()
            else:
                return

    def function_parens(self):
        save = self.i
        self.skip_blanks()
        if self.peek() == "(" and self.skip_empty_parens():
            return True
        self.i = save
        return False

    def skip_empty_parens(self):
        save = self.i
        self.i += 1
        self.skip_blanks()
        if self.peek() == ")":
            self.i += 1
            return True
        self.i = save
        return False

    def read_test(self):
        while self.i < self.n:
            self.skip_blanks()
            ch = self.peek()
            if ch == "":
                return
            if ch == "\n":
                self.i += 1
                continue
            if ch in "()<>&|!;":
                self.i += 1
                continue
            word = self.read_word()
            if word is None:
                self.i += 1
            elif word.static and word.value == "]]":
                return

    def simple_command(self, first, line):
        words = [first]
        while self.i < self.n:
            self.skip_blanks()
            if self.i >= self.n:
                break
            if self.redirect_at():
                self.read_redirect()
                continue
            ch = self.s[self.i]
            if ch in "\n;&|)":
                break
            if ch == "#":
                self.skip_comment()
                break
            if ch == "(":
                self.i += 1
                continue
            word = self.read_word()
            if word is None:
                self.i += 1
                continue
            words.append(word)

        assignments = []
        index = 0
        while index < len(words) and _ASSIGN.match(words[index].raw):
            assignments.append(words[index])
            index += 1
        rest = words[index:]
        declared = []
        if rest and rest[0].static and rest[0].value in ("export", "declare", "typeset", "local", "readonly"):
            declared = [item for item in rest[1:] if _ASSIGN.match(item.raw)]
        for word in (*assignments, *declared):
            name = _ASSIGN.match(word.raw).group(1)
            if name == "PATH":
                self.result.path_lines.append(line)
            self.result.assignments.setdefault(name, []).append(_assigned(word))
            self.result.assignment_sites.append((name, word, line, self.current_function()))
        if rest:
            self.result.commands.append(SimpleCommand(tuple(rest), line, tuple(assignments), self.current_function()))

    # -- redirections and here-documents -------------------------------------
    def redirect_at(self):
        match = _REDIRECT.match(self.s, self.i)
        if not match:
            return None
        if match.group(2) in ("<", ">") and self.s.startswith("(", match.end()):
            return None  # process substitution
        return match

    def read_redirect(self):
        match = self.redirect_at()
        self.i = match.end()
        op = match.group(2)
        self.skip_blanks()
        start = self.i
        word = self.read_word()
        if op in ("<<", "<<-") and word is not None:
            raw = self.s[start:self.i]
            quoted = any(ch in raw for ch in "'\"\\")
            self.heredocs.append((word.value, op == "<<-", quoted))

    def read_heredocs(self):
        pending, self.heredocs = self.heredocs, []
        for delimiter, strip_tabs, quoted in pending:
            body_start = self.i
            body_end = self.n
            while self.i < self.n:
                end = self.s.find("\n", self.i)
                end = self.n if end == -1 else end
                text = self.s[self.i:end].rstrip("\r")
                if strip_tabs:
                    text = text.lstrip("\t")
                if text == delimiter:
                    body_end = self.i
                    self.i = min(end + 1, self.n)
                    break
                self.i = min(end + 1, self.n)
            if not quoted:
                resume = self.i
                self.scan_expansions(body_start, body_end)
                self.i = resume

    def scan_expansions(self, start, end):
        """Parse the command substitutions in unquoted here-document text."""

        self.i = start
        while self.i < end:
            ch = self.s[self.i]
            if ch == "\\":
                self.i += 2
            elif ch == "$":
                self.read_dollar([])
            elif ch == "`":
                self.read_backtick([])
            else:
                self.i += 1

    # -- words ---------------------------------------------------------------
    def read_word(self):
        start = self.i
        value = []
        static = True
        items = ()
        while self.i < self.n:
            ch = self.s[self.i]
            if ch in "<>" and self.peek(1) == "(":
                self.i += 2
                begin = self.i - 2
                self.parse_list(close=")")
                value.append(self.s[begin:self.i])
                static = False
                continue
            if ch == "(":
                so_far = "".join(value)
                if self.i > start and self.s[self.i - 1] in "@!+*?":
                    begin = self.i
                    self.skip_balanced()
                    value.append(self.s[begin:self.i])
                    continue
                if _ARRAY_ASSIGN.match(so_far):
                    begin = self.i
                    self.i += 1
                    items = self.read_array()
                    value.append(self.s[begin:self.i])
                    continue
                break
            if ch in _META:
                break
            static &= self.read_word_part(ch, value)
        if self.i == start:
            return None
        return Word("".join(value), static, self.s[start:self.i], items)

    def read_word_part(self, ch, value):
        """Read one piece of a word starting at ch; return True if it is static."""

        if ch == "\\":
            following = self.peek(1)
            self.i += 2 if following else 1
            if following and following != "\n":
                value.append(following)
            return True
        if ch == "'":
            end = self.s.find("'", self.i + 1)
            end = self.n if end == -1 else end
            value.append(self.s[self.i + 1:end])
            self.i = end + 1
            return True
        if ch == '"':
            self.i += 1
            return self.read_double(value)
        if ch == "$":
            return self.read_dollar(value)
        if ch == "`":
            self.read_backtick(value)
            return False
        value.append(ch)
        self.i += 1
        return True

    def read_double(self, value):
        static = True
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == '"':
                self.i += 1
                return static
            if ch == "\\":
                following = self.peek(1)
                if following in ('"', "\\", "$", "`"):
                    value.append(following)
                elif following != "\n":
                    value.append(ch + following)
                self.i += 2
            elif ch == "$":
                static &= self.read_dollar(value)
            elif ch == "`":
                self.read_backtick(value)
                static = False
            else:
                value.append(ch)
                self.i += 1
        return static

    def read_dollar(self, value):
        start = self.i
        following = self.peek(1)
        if self.s.startswith("$((", self.i):
            self.i += 1
            self.skip_arith()
        elif following == "(":
            self.i += 2
            self.parse_list(close=")")
        elif following == "{":
            self.i += 2
            self.read_brace()
        elif following == "[":
            end = self.s.find("]", self.i)
            self.i = self.n if end == -1 else end + 1
        elif following == "'":
            self.i += 2
            value.append(self.read_ansi())
            return True
        elif following == '"':
            self.i += 2
            return self.read_double(value)
        elif following and _NAME_START.match(following):
            self.i = _PARAM.match(self.s, self.i + 1).end()
        elif following and following in "0123456789@*#?$!-":
            self.i += 2
        else:
            value.append("$")
            self.i += 1
            return True
        value.append(self.s[start:self.i])
        return False

    def read_ansi(self):
        out = []
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "'":
                self.i += 1
                break
            if ch == "\\" and self.i + 1 < self.n:
                escaped = self.s[self.i + 1]
                out.append(_ANSI.get(escaped, "\\" + escaped))
                self.i += 2
                continue
            out.append(ch)
            self.i += 1
        return "".join(out)

    def read_brace(self):
        depth = 1
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "\\":
                self.i += 2
            elif ch == "'":
                end = self.s.find("'", self.i + 1)
                self.i = self.n if end == -1 else end + 1
            elif ch == '"':
                self.i += 1
                self.read_double([])
            elif ch == "$":
                self.read_dollar([])
            elif ch == "`":
                self.read_backtick([])
            elif ch == "{":
                depth += 1
                self.i += 1
            elif ch == "}":
                depth -= 1
                self.i += 1
                if depth == 0:
                    return
            else:
                self.i += 1

    def skip_arith(self):
        """Skip (( ... )) starting at the first parenthesis, reading substitutions."""

        depth = 0
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "(":
                depth += 1
                self.i += 1
            elif ch == ")":
                depth -= 1
                self.i += 1
                if depth <= 0:
                    return
            elif ch == "$" and self.peek(1) in "({":
                self.read_dollar([])
            elif ch == "`":
                self.read_backtick([])
            else:
                self.i += 1

    def skip_balanced(self):
        depth = 0
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "\\":
                self.i += 2
                continue
            if ch in "'\"$`":
                self.read_word_part(ch, [])
                continue
            self.i += 1
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return

    def read_array(self):
        items = []
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == ")":
                self.i += 1
                break
            if ch in " \t\r\n" or (ch == "\\" and self.peek(1) == "\n"):
                self.i += 2 if ch == "\\" else 1
                continue
            if ch == "#":
                self.skip_comment()
                continue
            word = self.read_word()
            if word is None:
                self.i += 1
            else:
                items.append(word)
        return tuple(items)

    def read_backtick(self, value):
        start = self.i
        j = self.i + 1
        while j < self.n:
            if self.s[j] == "\\":
                j += 2
            elif self.s[j] == "`":
                break
            else:
                j += 1
        inner = self.s[self.i + 1:min(j, self.n)]
        inner = re.sub(r"\\([\\`$])", r"\1", inner)
        child = _Parser(inner, self.line_at(self.i + 1), self.result)
        child.subshell_function = self.current_function()
        child.parse_list()
        self.i = min(j + 1, self.n)
        value.append(self.s[start:self.i])


def _assigned(word):
    """The value an assignment word gives its variable, or None if not static."""

    if word.raw.split("=", 1)[0].endswith("+"):
        return None  # appends: the full value is not known here
    if word.raw.split("=", 1)[1].startswith("("):
        return word.items
    if not word.static:
        return None
    return word.value.split("=", 1)[1]


def parse(text, base_line=1, result=None):
    """Return the ParseResult of shell text. Lines count from base_line."""

    parser = _Parser(text, base_line, result)
    while parser.i < parser.n:
        parser.parse_list()  # a stray ")" at top level ends one list; keep going
    return parser.result
