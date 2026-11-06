"""Taint in Python files: where untrusted input reaches code or command execution.

Sources: sys.argv and argparse results (argv), os.environ / os.getenv
(env:NAME), input() and sys.stdin (stdin), responses of requests,
urllib and http.client (network), and web framework request data
(request.args, .form, .json, ...: network). Flow is followed through
assignments, expressions, calls, attribute access and function
parameters inside the file, without regard to order, so findings are
"inferred". shlex.quote, int, float, bool and len clean a value.
"""

from __future__ import annotations

import ast
from pathlib import Path

from .pyexec import _CALLS, _aliases, _dotted

SANITIZERS = frozenset(["shlex.quote", "pipes.quote", "int", "float", "bool", "len", "abs", "round",
                        "os.path.exists", "os.path.isfile", "os.path.isdir", "hash", "id", "type", "isinstance",
                        "any", "all", "callable", "hasattr", "issubclass", "re.match", "re.fullmatch", "re.search"])
NETWORK_CALLS = ("requests.get", "requests.post", "requests.put", "requests.request", "requests.Session",
                 "urllib.request.urlopen", "urllib.request.Request", "httpx.get", "httpx.post",
                 "http.client.HTTPConnection", "http.client.HTTPSConnection", "socket.socket", "socket.create_connection")
CODE_SINKS = {"eval": "eval", "exec": "exec", "compile": "compile", "pickle.loads": "pickle", "pickle.load": "pickle",
              "marshal.loads": "marshal", "yaml.load": "yaml.load", "yaml.unsafe_load": "yaml.load",
              "dill.loads": "pickle", "shelve.open": "pickle"}


class _Taint(ast.NodeVisitor):
    def __init__(self, tree, argv_labels, env_labels, env_default):
        self.tree = tree
        self.aliases = _aliases(tree)
        self.argv = set(argv_labels)
        self.env = env_labels
        self.env_default = env_default
        self.vars = {}      # (function or None, name) -> labels
        self.params = {}    # function name -> {param name: labels}
        self.returns = {}   # function name -> labels
        self.functions = {}
        self.scope_of = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
                for child in ast.walk(node):
                    if child is not node:
                        self.scope_of.setdefault(id(child), node.name)

    def name(self, node):
        return _dotted(node, self.aliases)

    def scope(self, node):
        return self.scope_of.get(id(node))

    def lookup(self, name, scope):
        labels = set(self.vars.get((scope, name), ()))
        if scope is not None:
            labels |= self.params.get(scope, {}).get(name, set())
            if (scope, name) not in self.vars:
                labels |= self.vars.get((None, name), set())
        return labels

    # -- labels of an expression --------------------------------------------------
    def labels(self, node, scope):
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            return self.lookup(node.id, scope)
        if isinstance(node, ast.IfExp):  # the condition picks a value; it is not the value
            return self.labels(node.body, scope) | self.labels(node.orelse, scope)
        if isinstance(node, (ast.Compare, ast.Constant)) or (
                isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)):
            return set()
        dotted = self.name(node) if isinstance(node, ast.Attribute) else None
        if dotted == "sys.argv":
            return set(self.argv)
        if dotted in ("sys.stdin",):
            return {"stdin"}
        if dotted == "os.environ":
            return {"env"} if self.env_default else set()
        if dotted and dotted.split(".")[0] == "request" and len(dotted.split(".")) >= 2 and dotted.split(".")[1] in (
                "args", "form", "values", "json", "data", "files", "headers", "cookies", "get_json", "query_params", "body"):
            return {"network"}
        if isinstance(node, ast.Subscript):
            base = self.name(node.value)
            if base == "os.environ":
                key = node.slice.value if isinstance(node.slice, ast.Constant) else None
                return self._env(key)
            return self.labels(node.value, scope) | self.labels(node.slice, scope)
        if isinstance(node, ast.Call):
            function = self.name(node.func)
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            if function in SANITIZERS:
                return set()
            if function in ("os.getenv", "os.environ.get"):
                key = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                return self._env(key)
            if function == "input" or (function or "").startswith("sys.stdin."):
                return {"stdin"}
            if function in NETWORK_CALLS:
                return {"network"}
            if function and function.endswith(".parse_args") or function and function.endswith(".parse_known_args"):
                return set(self.argv)
            if isinstance(node.func, ast.Name) and node.func.id in self.functions:
                labels = set(self.returns.get(node.func.id, ()))
                return labels
            labels = set()
            if isinstance(node.func, ast.Attribute):
                labels |= self.labels(node.func.value, scope)
            for argument in arguments:
                labels |= self.labels(argument, scope)
            return labels
        labels = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.expr, ast.comprehension, ast.keyword, ast.FormattedValue)):
                labels |= self.labels(child, scope)
        return labels

    def _env(self, key):
        if key and key in self.env:
            return set(self.env[key])
        if not self.env_default:
            return set()
        return {f"env:{key}" if key else "env"}

    # -- propagation ----------------------------------------------------------------
    def bind(self, target, labels, scope):
        changed = False
        if isinstance(target, ast.Name):
            key = (scope, target.id)
            before = self.vars.get(key, set())
            if labels and not labels <= before:
                self.vars[key] = before | labels
                changed = True
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                changed |= self.bind(item, labels, scope)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            changed |= self.bind(base, labels, scope)
        return changed

    def propagate(self):
        for _ in range(25):
            changed = False
            for node in ast.walk(self.tree):
                scope = self.scope(node)
                if isinstance(node, ast.Assign):
                    labels = self.labels(node.value, scope)
                    for target in node.targets:
                        changed |= self.bind(target, labels, scope)
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None or isinstance(node, ast.NamedExpr):
                    changed |= self.bind(node.target, self.labels(node.value, scope), scope)
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                    changed |= self.bind(node.target, self.labels(node.iter, scope), scope)
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        if item.optional_vars is not None:
                            changed |= self.bind(item.optional_vars, self.labels(item.context_expr, scope), scope)
                elif isinstance(node, ast.Return) and scope is not None and node.value is not None:
                    labels = self.labels(node.value, scope)
                    if labels and not labels <= self.returns.get(scope, set()):
                        self.returns[scope] = self.returns.get(scope, set()) | labels
                        changed = True
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in self.functions:
                    definition = self.functions[node.func.id]
                    names = [argument.arg for argument in definition.args.args]
                    params = self.params.setdefault(definition.name, {})
                    pairs = list(zip(names, node.args)) + [(keyword.arg, keyword.value) for keyword in node.keywords if keyword.arg]
                    for param, value in pairs:
                        labels = self.labels(value, scope)
                        if labels and not labels <= params.get(param, set()):
                            params[param] = params.get(param, set()) | labels
                            changed = True
            if not changed:
                return


def python_taint(path, argv_labels=("argv",), env_labels=None, env_default=True, text=None):
    """Return (findings, calls) for a Python file.

    calls lists the programs the file starts with tainted arguments:
    (program name, [labels per argument], line), for the cross-language
    analysis to follow.
    """

    if text is None:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [], []
    taint = _Taint(tree, argv_labels, env_labels or {}, env_default)
    taint.propagate()
    findings, calls = [], []

    def finding(node, sink, detail, labels, expression):
        findings.append({"file": str(path), "line": node.lineno, "sink": sink, "detail": detail,
                         "sources": sorted(labels), "expression": ast.unparse(expression)[:120]})

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scope = taint.scope(node)
        function = taint.name(node.func)
        if function in CODE_SINKS or (isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "compile")
                                      and node.func.id not in taint.functions):
            sink = CODE_SINKS.get(function, function)
            if node.args:
                labels = taint.labels(node.args[0], scope)
                if sink == "yaml.load" and any("Safe" in ast.unparse(keyword.value) for keyword in node.keywords):
                    labels = set()
                if labels:
                    finding(node, sink, f"{function}() of input", labels, node.args[0])
            continue
        if function not in _CALLS:
            continue
        index, form = _CALLS[function]
        argument = node.args[index] if len(node.args) > index else None
        if argument is None:
            for keyword in node.keywords:
                if keyword.arg in ("args", "cmd", "file", "path"):
                    argument = keyword.value
        if argument is None:
            continue
        shell = form == "shell"
        for keyword in node.keywords:
            if keyword.arg == "shell" and not (isinstance(keyword.value, ast.Constant) and not keyword.value.value):
                shell = True
        if shell:
            labels = taint.labels(argument, scope)
            if labels:
                finding(node, "shell", f"{function}() runs input through a shell", labels, argument)
            continue
        if isinstance(argument, (ast.List, ast.Tuple)) and argument.elts:
            program, arguments = argument.elts[0], argument.elts[1:]
        elif form == "file":
            program, arguments = argument, node.args[index + 1:]
            if arguments and isinstance(arguments[0], (ast.List, ast.Tuple)):
                arguments = arguments[0].elts[1:]
        else:
            program, arguments = argument, []
        program_labels = taint.labels(program, scope)
        if program_labels:
            finding(node, "command", f"{function}() runs a program named by input", program_labels, program)
            continue
        argument_labels = [sorted(taint.labels(item, scope)) for item in arguments]
        if any(argument_labels) and isinstance(program, ast.Constant) and isinstance(program.value, str):
            calls.append((program.value, argument_labels, node.lineno))
    return findings, calls
