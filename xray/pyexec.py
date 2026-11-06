"""The commands a Python file starts: subprocess, os.system, os.exec* and friends.

Calls are found by reading the code (nothing is imported or run), with
import aliases followed (``import subprocess as sp``, ``from os import
system``). A command given as a literal string or list is reported with
its line. A shell command string (``shell=True``, ``os.system``,
``os.popen``) is read with XRAY's shell parser, so the commands inside
it are reported too. A command held in a variable that the file only
ever assigns literal values is resolved and marked as a guess; any other
computed command is listed as dynamic.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

# function -> (index of the command argument, how the command is given)
#   "argv"  a list/tuple whose first item is the program, or a string program
#   "shell" a shell command string
#   "file"  a program path or name, with its arguments given separately
_CALLS = {
    "subprocess.run": (0, "argv"),
    "subprocess.call": (0, "argv"),
    "subprocess.check_call": (0, "argv"),
    "subprocess.check_output": (0, "argv"),
    "subprocess.Popen": (0, "argv"),
    "subprocess.getoutput": (0, "shell"),
    "subprocess.getstatusoutput": (0, "shell"),
    "os.system": (0, "shell"),
    "os.popen": (0, "shell"),
    "asyncio.create_subprocess_shell": (0, "shell"),
    "asyncio.create_subprocess_exec": (0, "file"),
    "pty.spawn": (0, "argv"),
}
for _name in ("execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
              "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
              "posix_spawn", "posix_spawnp"):
    _CALLS[f"os.{_name}"] = (1 if _name.startswith("spawn") else 0, "file")


@dataclass(frozen=True)
class PythonExec:
    """Commands a Python file starts. Same shape as shellscan.ShellFacts."""

    commands: dict = field(default_factory=dict)
    via: dict = field(default_factory=dict)
    dynamic: tuple = ()


def _aliases(tree):
    """Map local names to the dotted names they stand for."""

    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _dotted(node, aliases):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    head = aliases.get(node.id, node.id)
    return ".".join([head, *reversed(parts)])


def _literal(node):
    """A str, or a list of str for a literal sequence; None when computed."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        first = node.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return [first.value]
    return None


def _constants(tree):
    """Names assigned only literal values: {name: [values]}."""

    values = {}
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            values.setdefault(node.target.id, []).append(None)
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                values.setdefault(target.id, []).append(_literal(value))
            elif isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    if isinstance(item, ast.Name):
                        values.setdefault(item.id, []).append(None)
    return {name: found for name, found in values.items() if None not in found}


def _keyword(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def python_exec(path):
    """Return PythonExec for a Python file (empty if it cannot be parsed)."""

    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return PythonExec()
    return _read(tree)


def _read(tree):
    from .shellscan import facts_of_text

    aliases = _aliases(tree)
    constants = _constants(tree)
    commands, via, dynamic = {}, {}, []

    def add(name, line, how):
        name = name.strip()
        if not name:
            return
        commands.setdefault(name, set()).add(line)
        via.setdefault(name, how)

    def shell_code(text, line, how):
        facts = facts_of_text(text)
        for name in facts.commands:
            add(name, line, f"{how} (shell)")
        for _, word in facts.dynamic:
            dynamic.append((line, f"{how}: {word}"))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = _dotted(node.func, aliases)
        if function not in _CALLS:
            continue
        index, form = _CALLS[function]
        argument = node.args[index] if len(node.args) > index else _keyword(node, "args" if form == "argv" else "cmd")
        if argument is None and form == "file":
            argument = _keyword(node, "file") or _keyword(node, "path") or _keyword(node, "program")
        if argument is None:
            continue
        shell = form == "shell"
        flag = _keyword(node, "shell")
        if form == "argv" and isinstance(flag, ast.Constant) and flag.value:
            shell = True
        elif form == "argv" and flag is not None and not isinstance(flag, ast.Constant):
            shell = None  # decided at run time

        how = function
        options = [_literal(argument)]
        if options[0] is None and isinstance(argument, ast.Name) and argument.id in constants:
            options = constants[argument.id]
            how = f"{function} through {argument.id}"
        if None in options:
            dynamic.append((node.lineno, f"{function}({ast.unparse(argument)[:60]})"))
            continue
        for value in options:
            if shell is None:
                dynamic.append((node.lineno, f"{function}: shell= decided at run time"))
            elif isinstance(value, list):
                add(value[0], node.lineno, how)
            elif shell:
                shell_code(value, node.lineno, how)
            else:  # a string without a shell is the program itself
                add(value, node.lineno, how)

    return PythonExec(
        {name: sorted(lines) for name, lines in sorted(commands.items())},
        via,
        tuple(sorted(dynamic)),
    )
