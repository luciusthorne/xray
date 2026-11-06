"""Taint in shell scripts: where untrusted input reaches code or command execution.

Sources: the script's arguments ($1, $@, getopts), standard input (read,
mapfile), output of network commands ($(curl ...)), and environment
variables the script reads without assigning them. Labels say which.

Flow is followed through assignments, local variables, for loops,
command substitutions and function arguments, without regard to order
(an assignment anywhere taints the variable everywhere in its scope):
this over-approximates, so every finding is "inferred", never proof.

Sinks, most severe first: running a command whose name is tainted, eval,
sh -c, source, trap; then tainted data passed to another program, which
the cross-language analysis (xray.taint) follows into that program.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .shellscan import BUILTINS, SHELLS, WRAPPERS, _wrapped
from .shparse import parse

_VAR = re.compile(r"\$\{?#?!?([A-Za-z_][A-Za-z0-9_]*)")
_POSITIONAL = re.compile(r"\$\{?(\d+|@|\*)\}?")
# a network download in command position inside $( ) or ` `, or after a pipe there
_NETWORK = re.compile(r"(?:\$\(|`|[|;&]|\b(?:command|exec|sudo|env))\s*(curl|wget|nc|ncat|netcat|socat|aria2c)(?=[\s)`]|$)")
_ARRAY_REF = re.compile(r'^"?\$\{([A-Za-z_][A-Za-z0-9_]*)\[(?:@|\*|0)\]\}"?$')
# Variables the shell sets itself: not input.
SHELL_SET = frozenset([
    "PWD", "OLDPWD", "RANDOM", "LINENO", "SECONDS", "PPID", "UID", "EUID", "BASHPID", "BASH", "BASH_SOURCE",
    "BASH_VERSION", "BASH_LINENO", "FUNCNAME", "OPTIND", "REPLY", "IFS", "HOSTNAME", "HOSTTYPE", "OSTYPE",
    "MACHTYPE", "SHLVL", "PIPESTATUS", "EPOCHSECONDS", "EPOCHREALTIME", "SRANDOM", "BASH_REMATCH", "COLUMNS",
    "LINES", "GROUPS", "DIRSTACK", "SHELLOPTS", "BASHOPTS", "BASH_ARGV", "BASH_ARGC", "BASH_COMMAND", "OPTARG",
    "OPTERR", "MAPFILE", "COMP_WORDS", "COMP_CWORD", "COMP_LINE", "COMPREPLY",
])
HIGH_SINKS = ("command", "eval", "sh -c", "source", "trap")
DANGEROUS_ARGS = frozenset(["rm", "chmod", "chown", "mv", "cp", "dd", "find", "xargs", "tar", "rsync", "ssh",
                            "scp", "curl", "wget", "git", "sed", "awk", "perl", "python", "python3"])


@dataclass
class ShellTaint:
    findings: list = field(default_factory=list)
    calls: list = field(default_factory=list)  # (command name or path, [labels per argument], line)
    exported: dict = field(default_factory=dict)


def _strip_single_quotes(raw):
    """raw with single-quoted text and escaped dollars removed (they expand nothing)."""

    out, quote, index = [], None, 0
    while index < len(raw):
        ch = raw[index]
        if ch == "\\" and quote != "'":
            index += 2
            continue
        if quote is None and ch == "'":
            end = raw.find("'", index + 1)
            index = len(raw) if end == -1 else end + 1
            continue
        if ch == '"':
            quote = None if quote == '"' else '"'
        out.append(ch)
        index += 1
    return "".join(out)


def _unquoted_expansion(raw):
    """True when raw has a $ expansion outside double quotes (subject to splitting and globbing)."""

    quote, index = None, 0
    while index < len(raw):
        ch = raw[index]
        if ch == "\\":
            index += 2
            continue
        if quote is None and ch == "'":
            end = raw.find("'", index + 1)
            index = len(raw) if end == -1 else end + 1
            continue
        if ch == '"':
            quote = None if quote == '"' else '"'
        elif ch == "$" and quote is None:
            return True
        index += 1
    return False


_INTERPRETER = re.compile(r"^(python[0-9.]*|perl|ruby|node|bash|sh|dash|zsh|ksh)$")
_SELF_DIR = re.compile(
    r'\$\(\s*dirname\s+"?\$(?:0|\{0\}|\{BASH_SOURCE(?:\[0\])?\}|BASH_SOURCE)"?\s*\)'
    r'|`dirname\s+"?\$0"?`|\$\{0%/\*\}|\$\{BASH_SOURCE(?:\[0\])?%/\*\}'
)


class _Analysis:
    def __init__(self, result, argv_labels, env_labels, env_default, script_dir=None):
        self.result = result
        self.script_dir = script_dir
        # variables that hold the script's own directory: DIR=$(cd "$(dirname "$0")" && pwd)
        self.dir_vars = {
            name for name, word, _, _ in result.assignment_sites
            if _SELF_DIR.search(word.raw) or re.search(r"\$\(\s*cd\s+\S*dirname", word.raw)
        }
        self.functions = set(result.functions)
        self.argv = set(argv_labels)
        self.env = env_labels
        self.env_default = env_default
        self.vars = {}       # (scope, name) -> labels
        self.heads = {}      # (scope, name) -> labels of an array's first element
        self.params = {}     # function -> {position or "*": labels}
        self.locals = {}     # function -> names declared local
        self.assigned = {name for name, _, _, _ in result.assignment_sites} | {name for name, _, _, _ in result.loops}
        self.indirect = []  # (name, words, scope): assignments made through eval or printf -v
        for command in result.commands:
            words = command.words
            if not words or not words[0].static:
                continue
            if words[0].value in ("read", "mapfile", "readarray", "getopts"):
                self.assigned.update(word.value for word in words[1:] if not word.value.startswith("-"))
            elif words[0].value == "eval":
                for word in words[1:]:
                    for name in re.findall(r"(?:^|[\s;'\"])([A-Za-z_][A-Za-z0-9_]*)\+?=", word.raw):
                        self.assigned.add(name)
                        self.indirect.append((name, words[1:], command.function))
            elif words[0].value == "printf":
                for position, word in enumerate(words[1:-1], 1):
                    if word.value == "-v" and words[position + 1].static:
                        self.assigned.add(words[position + 1].value)
                        self.indirect.append((words[position + 1].value, words[position + 2:], command.function))
        for command in result.commands:
            if command.function and command.words and command.words[0].static and command.words[0].value in (
                    "local", "declare", "typeset"):
                for word in command.words[1:]:
                    name = word.raw.split("=", 1)[0].lstrip("-")
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                        self.locals.setdefault(command.function, set()).add(name)

    # -- labels of a word ------------------------------------------------------
    def scope_of(self, name, scope):
        if scope is not None and name in self.locals.get(scope, ()):
            return scope
        return None

    def var_labels(self, name, scope):
        key = (self.scope_of(name, scope), name)
        labels = set(self.vars.get(key, ()))
        if name not in self.assigned and name not in SHELL_SET:
            labels |= self.env.get(name, set()) or ({f"env:{name}"} if self.env_default else set())
        if name == "OPTARG":
            labels |= self.argv
        return labels

    def positional(self, which, scope):
        if scope is None:
            return set(self.argv) if which != "0" else set()
        params = self.params.get(scope, {})
        if which in ("@", "*"):
            out = set()
            for labels in params.values():
                out |= labels
            return out
        return set(params.get(which, set())) | set(params.get("*", set()))

    def head_labels(self, word, scope):
        """Labels of the command name a word gives: for "${array[@]}" only the array's first element."""

        match = _ARRAY_REF.match(word.raw)
        if match:
            key = (self.scope_of(match.group(1), scope), match.group(1))
            if key in self.heads:
                return set(self.heads[key])
        return self.labels(word, scope)

    def array_words(self, word, scope):
        """The element words of "${array[@]}" when the array is assigned once, else None."""

        match = _ARRAY_REF.match(word.raw)
        if not match:
            return None
        sites = [item for name, item, _, where in self.result.assignment_sites
                 if name == match.group(1) and item.items]
        return list(sites[0].items) if len(sites) == 1 else None

    def path_of(self, word):
        """A static path for a word, resolving the script's own directory; None if unknown."""

        if word.static:
            return word.value
        if self.script_dir is None:
            return None
        raw = _SELF_DIR.sub(self.script_dir, word.raw)
        for name in self.dir_vars:
            raw = re.sub(r"\$\{?" + name + r"\}?(?![A-Za-z0-9_])", self.script_dir, raw)
        if "$" in raw or "`" in raw:
            return None
        return raw.replace('"', "").replace("'", "")

    def labels(self, word, scope):
        raw = _strip_single_quotes(word.raw)
        labels = set()
        for which in _POSITIONAL.findall(raw):
            labels |= self.positional(which, scope)
        for name in _VAR.findall(raw):
            labels |= self.var_labels(name, scope)
        if ("$(" in raw or "`" in raw) and _NETWORK.search(raw):
            labels.add("network")
        for item in word.items:
            labels |= self.labels(item, scope)
        return labels

    # -- propagation -------------------------------------------------------------
    def taint_var(self, name, scope, labels):
        if not labels:
            return False
        key = (self.scope_of(name, scope), name)
        before = self.vars.get(key, set())
        if labels <= before:
            return False
        self.vars[key] = before | labels
        return True

    def propagate(self):
        for _ in range(25):
            changed = False
            for name, word, _, scope in self.result.assignment_sites:
                value = word.raw.split("=", 1)[1] if "=" in word.raw else ""
                inner = type(word)(value, word.static, value, word.items)
                changed |= self.taint_var(name, scope, self.labels(inner, scope))
                if word.items and not word.raw.split("=", 1)[0].endswith("+"):
                    key = (self.scope_of(name, scope), name)
                    head = self.labels(word.items[0], scope) if word.items[0] else set()
                    if not head <= self.heads.get(key, set()) or key not in self.heads:
                        self.heads[key] = self.heads.get(key, set()) | head
                        changed = True
                elif word.items or "=" in word.raw and not value.startswith("("):
                    key = (self.scope_of(name, scope), name)
                    if key in self.heads and word.raw.split("=", 1)[0].endswith("+"):
                        continue
                    labels = self.labels(inner, scope)
                    if key in self.heads and not labels <= self.heads[key]:
                        self.heads[key] |= labels  # assigned as a scalar somewhere: the whole value may lead
                        changed = True
            for name, words, scope in self.indirect:
                labels = set()
                for item in words:
                    labels |= self.labels(item, scope)
                changed |= self.taint_var(name, scope, labels)
            for name, words, _, scope in self.result.loops:
                labels = set()
                for item in words:
                    labels |= self.labels(item, scope)
                changed |= self.taint_var(name, scope, labels)
            for command in self.result.commands:
                words = command.words
                if not words or not words[0].static:
                    continue
                name = words[0].value
                if name in ("read", "mapfile", "readarray"):
                    for word in words[1:]:
                        if not word.value.startswith("-") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word.value):
                            changed |= self.taint_var(word.value, command.function, {"stdin"})
                elif name == "getopts" and len(words) >= 3:
                    changed |= self.taint_var(words[2].value, command.function, set(self.argv))
                elif name in self.functions:
                    params = self.params.setdefault(name, {})
                    for position, word in enumerate(words[1:], 1):
                        labels = self.labels(word, command.function)
                        key = "*" if word.raw in ('"$@"', "$@", '"$*"', "$*") else str(position)
                        if labels and not labels <= params.get(key, set()):
                            params[key] = params.get(key, set()) | labels
                            changed = True
            if not changed:
                return


def shell_taint(path, argv_labels=("argv",), env_labels=None, env_default=True, text=None):
    """Return ShellTaint for a shell script.

    argv_labels label the script's own arguments; env_labels gives labels
    for specific environment variables (from a caller's export), and with
    env_default every other unassigned variable counts as env:NAME input.
    """

    if text is None:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ShellTaint()
    result = parse(text)
    analysis = _Analysis(result, argv_labels, env_labels or {}, env_default, str(Path(path).resolve().parent))
    # a name assigned anywhere in the text, even in a string run later by eval, is not environment input
    analysis.assigned |= set(re.findall(r"(?:^|[\s;'\"{(`])([A-Za-z_][A-Za-z0-9_]*)\+?=", text, re.MULTILINE))
    analysis.propagate()
    out = ShellTaint()

    for command in result.commands:
        words = list(command.words)
        scope = command.function
        if words and words[0].static and words[0].value in ("export", "declare", "typeset", "local", "readonly"):
            if words[0].value == "export" or any(word.value == "-x" for word in words[1:]):
                for word in words[1:]:
                    name = word.raw.split("=", 1)[0]
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                        labels = analysis.var_labels(name, scope)
                        if labels:
                            out.exported[name] = labels
            continue
        _sinks(analysis, words, command.line, scope, out, path)
    return out


def _finding(out, path, line, sink, detail, labels, word):
    out.findings.append({
        "file": str(path), "line": line, "sink": sink, "detail": detail,
        "sources": sorted(labels), "expression": word,
    })


def _sinks(analysis, words, line, scope, out, path):
    while words and words[0].static and words[0].value in ("exec", "command", "nohup", "time", "!", "builtin"):
        if words[0].value == "command" and len(words) > 1 and words[1].value in ("-v", "-V"):
            return
        words = words[1:]
    if not words:
        return
    first = words[0]
    expanded = analysis.array_words(first, scope)
    if expanded:
        words = [*expanded, *words[1:]]
        first = words[0]
    first_labels = analysis.head_labels(first, scope)
    if first_labels:
        _finding(out, path, line, "command", f"runs a command named by input: {first.raw}", first_labels, first.raw)
        return
    name = analysis.path_of(first)
    if name is None:
        return
    rest = words[1:]
    labels_of = [analysis.labels(word, scope) for word in rest]

    if _INTERPRETER.match(Path(name).name) and not any(
            word.static and word.value.startswith("-") and "c" in word.value[1:] and not word.value.startswith("--")
            for word in rest):
        # python3 script.py ARGS: the input goes to the script, not the interpreter
        for position, word in enumerate(rest):
            if word.static and word.value.startswith("-"):
                if word.value in ("-m",):
                    return
                continue
            script = analysis.path_of(word)
            remaining = labels_of[position + 1:]
            if script is not None and any(remaining):
                out.calls.append((script, [sorted(labels) for labels in remaining], line))
            return
        return

    if name == "eval":
        merged = set().union(*labels_of) if labels_of else set()
        if merged:
            _finding(out, path, line, "eval", "eval of input", merged, " ".join(word.raw for word in rest)[:120])
        return
    if name in ("source", "."):
        if rest and labels_of[0]:
            _finding(out, path, line, "source", f"sources a file named by input: {rest[0].raw}", labels_of[0], rest[0].raw)
        return
    if name == "trap":
        if rest and labels_of[0]:
            _finding(out, path, line, "trap", "trap runs input as code", labels_of[0], rest[0].raw)
        return
    if Path(name).name in SHELLS:
        for position, word in enumerate(rest):
            value = word.value
            if value.startswith("-") and not value.startswith("--") and "c" in value[1:] and position + 1 < len(rest):
                if labels_of[position + 1]:
                    _finding(out, path, line, "sh -c", f"{Path(name).name} -c runs input as code",
                             labels_of[position + 1], rest[position + 1].raw)
                return
    if name in BUILTINS or name in ("local", "export", "declare", "readonly", "typeset", "read", "printf",
                                    "echo", "test", "[", "[["):
        return
    if name in WRAPPERS:
        values = [word.value if word.static else "\0" for word in rest]
        wrapped = _wrapped(name, values)
        start = len(rest) - len(wrapped)
        if wrapped:
            _sinks(analysis, rest[start:], line, scope, out, path)
        return
    if name == "find":
        for position, word in enumerate(rest):
            if word.static and word.value in ("-exec", "-execdir", "-ok", "-okdir"):
                _sinks(analysis, rest[position + 1:], line, scope, out, path)
        return
    if name in analysis.functions:
        return  # followed through the function's parameters
    if any(labels_of):
        merged = set().union(*labels_of)
        out.calls.append((name, [sorted(labels) for labels in labels_of], line))
        if Path(name).name in DANGEROUS_ARGS:
            unquoted = [word.raw for word, labels in zip(rest, labels_of) if labels and _unquoted_expansion(word.raw)]
            if unquoted:
                _finding(out, path, line, "argument", f"unquoted input split into arguments of {Path(name).name}: "
                         + ", ".join(unquoted[:3]), merged, " ".join(unquoted)[:120])
