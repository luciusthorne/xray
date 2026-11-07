"""Lisp-family code: Emacs Lisp, Scheme (Guile), Common Lisp and Clojure.

Lisp code is data, so it can be read exactly: a small S-expression reader
finds every definition with its line span, every call (the head of an
evaluated list), and every module it loads (require, use-modules, load, ns).
Nothing is evaluated.
"""

import gzip
import os
from dataclasses import dataclass, field
from pathlib import Path

from .analyzers import Analyzer, registry
from .model import Edge
from .symbols import Symbol

SUFFIXES = {
    ".el": "elisp",
    ".scm": "scheme", ".ss": "scheme", ".sld": "scheme", ".sls": "scheme", ".rkt": "scheme",
    ".lisp": "common-lisp", ".lsp": "common-lisp", ".asd": "common-lisp",
    ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure", ".bb": "clojure",
    ".fnl": "fennel",
}
INTERPRETERS = {
    "guile": "scheme", "racket": "scheme", "csi": "scheme", "chicken": "scheme", "gosh": "scheme",
    "scheme": "scheme", "chez": "scheme", "chezscheme": "scheme", "petite": "scheme", "chibi-scheme": "scheme",
    "sbcl": "common-lisp", "clisp": "common-lisp", "ecl": "common-lisp", "ccl": "common-lisp",
    "emacs": "elisp", "bb": "clojure", "clojure": "clojure", "clj": "clojure", "fennel": "fennel",
}
DIALECT_NAMES = {"elisp": "Emacs Lisp", "scheme": "Scheme", "common-lisp": "Common Lisp",
                 "clojure": "Clojure", "fennel": "Fennel"}


def is_lisp_name(path):
    name = Path(path).name.lower()
    return name.endswith(".el.gz") or Path(name).suffix in SUFFIXES


def dialect(path, first_line=""):
    """The Lisp dialect of a file from its name or shebang interpreter."""

    name = Path(path).name.lower()
    if name.endswith(".el.gz"):
        return "elisp"
    suffix = Path(name).suffix
    if suffix in SUFFIXES:
        return SUFFIXES[suffix]
    if first_line.startswith("#!"):
        from .entrypoints import _interpreter

        return INTERPRETERS.get(_interpreter(first_line))
    return None


def read_text(path):
    path = Path(path)
    if path.name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8", errors="replace")


# -- reader -------------------------------------------------------------------

@dataclass
class Node:
    kind: str                 # "list", "atom", "string"
    text: str = ""            # atom or string text; list opener for lists
    line: int = 0
    end: int = 0
    items: list = field(default_factory=list)
    quoted: bool = False      # inside ' or ` (data, not code)


_CLOSERS = {"(": ")", "[": "]", "{": "}"}
_DELIMITERS = set("()[]{}\"; \t\r\n")


def parse(text, lang="scheme"):
    """Top-level forms as Nodes. Unbalanced input yields what could be read."""

    forms, stack = [], []
    i, n, line = 0, len(text), 1
    pending_quote = []  # quote markers waiting for the next datum
    unquote = [False]   # a , or ,@ makes the next datum code again inside a backquote

    def add(node):
        nonlocal pending_quote
        if pending_quote:
            node.quoted = True
            pending_quote.pop()
        if stack:
            if stack[-1].quoted:
                node.quoted = True
            if unquote[0]:
                node.quoted, unquote[0] = False, False
            stack[-1].items.append(node)
        else:
            forms.append(node)
        _mark(node)

    def _mark(node):
        if node.quoted:
            for child in node.items:
                child.quoted = True

    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r\f":
            i += 1
        elif c == ";":
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("#|", i):  # block comment (Common Lisp, Scheme), may nest
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("#|", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("|#", i):
                    depth, i = depth - 1, i + 2
                else:
                    line += text[i] == "\n"
                    i += 1
        elif text.startswith("#;", i) or (lang == "clojure" and text.startswith("#_", i)):
            pending_quote.append("#;")  # datum comment: read and drop the next datum as data
            i += 2
        elif c == '"':
            start_line, j = line, i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                if j < n and text[j] == "\n":
                    line += 1
                j += 1
            add(Node("string", text[i + 1:j], start_line, line))
            i = j + 1
        elif c == "?" and lang == "elisp" and (i == 0 or text[i - 1] in _DELIMITERS or text[i - 1] in "'`,"):
            # character literal: ?a ?( ?\( ?\C-x
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2
                while j < n and text[j] not in _DELIMITERS:
                    j += 1
            else:
                j += 1
            add(Node("atom", text[i:j], line, line))
            i = j
        elif text.startswith("#\\", i):  # Scheme / Common Lisp character: #\( #\space
            j = i + 3
            while j < n and text[j] not in _DELIMITERS:
                j += 1
            add(Node("atom", text[i:j], line, line))
            i = j
        elif lang == "clojure" and c == "\\" and i + 1 < n:  # Clojure character: \( \newline
            j = i + 2
            while j < n and text[j] not in _DELIMITERS:
                j += 1
            add(Node("atom", text[i:j], line, line))
            i = j
        elif c in "'`" or (c == "#" and i + 1 < n and text[i + 1] in "'`"):
            pending_quote.append(c)
            i += 2 if c == "#" else 1
            if c == "#":
                # #'name is a function reference: keep it code, not data
                pending_quote.pop()
                j = i
                while j < n and text[j] not in _DELIMITERS:
                    j += 1
                add(Node("atom", "#'" + text[i:j], line, line))
                i = j
        elif c == ",":
            i += 2 if text.startswith(",@", i) else 1  # unquote: back to code inside a backquote
            unquote[0] = bool(stack and stack[-1].quoted)
        elif c in "([{" or (c == "#" and i + 1 < n and text[i + 1] in "([{"):
            if c == "#":
                i += 1
                c = text[i]
            node = Node("list", c, line)
            if pending_quote:
                node.quoted = True
                pending_quote.pop()
            if stack and stack[-1].quoted:
                node.quoted = True
            if unquote[0]:
                node.quoted, unquote[0] = False, False
            stack.append(node)
            i += 1
        elif c in ")]}":
            if stack:
                node = stack.pop()
                node.end = line
                if stack:
                    stack[-1].items.append(node)
                else:
                    forms.append(node)
            i += 1
        else:
            j = i
            while j < n and text[j] not in _DELIMITERS:
                if text[j] == "\\":
                    j += 1
                j += 1
            add(Node("atom", text[i:j], line, line))
            i = j
    while stack:  # unbalanced: close what is open
        node = stack.pop()
        node.end = line
        (stack[-1].items if stack else forms).append(node)
    return forms


# -- what the code defines, calls and loads ------------------------------------

_DEFINERS = {
    "elisp": {"defun": "function", "defmacro": "function", "defsubst": "function", "cl-defun": "function",
              "cl-defmacro": "function", "cl-defsubst": "function", "cl-defgeneric": "function",
              "cl-defmethod": "method", "define-inline": "function", "define-minor-mode": "function",
              "define-derived-mode": "function", "define-globalized-minor-mode": "function",
              "defvar": "variable", "defcustom": "variable", "defconst": "variable", "defvar-local": "variable",
              "defface": "variable", "defgroup": "variable", "cl-defstruct": "class", "defclass": "class"},
    "scheme": {"define": "function", "define-public": "function", "define*": "function",
               "define*-public": "function", "define-syntax": "function", "define-macro": "function",
               "define-syntax-rule": "function", "define-record-type": "class", "define-module": "module",
               "define-library": "module", "library": "module"},
    "common-lisp": {"defun": "function", "defmacro": "function", "defgeneric": "function",
                    "defmethod": "method", "define-compiler-macro": "function", "defvar": "variable",
                    "defparameter": "variable", "defconstant": "variable", "defclass": "class",
                    "defstruct": "class", "defpackage": "module", "define-condition": "class"},
    "clojure": {"defn": "function", "defn-": "function", "defmacro": "function", "defmulti": "function",
                "defmethod": "method", "def": "variable", "defonce": "variable", "defrecord": "class",
                "deftype": "class", "defprotocol": "interface", "ns": "module"},
    "fennel": {"fn": "function", "lambda": "function", "macro": "function", "local": "variable",
               "global": "variable"},
}

# Forms whose second element is not code (argument lists) and binding forms whose
# binding pairs are not calls.
_ARGLIST_FORMS = {"lambda", "fn", "cl-function", "defun", "defmacro", "cl-defun", "cl-defmacro", "defsubst",
                  "defn", "defn-", "defmethod", "cl-defmethod", "define*", "lambda*", "named-lambda"}
_BINDING_FORMS = {"let", "let*", "letrec", "letrec*", "let-values", "let*-values", "when-let", "if-let",
                  "when-let*", "if-let*", "and-let*", "pcase-let", "pcase-let*", "cl-letf", "cl-flet",
                  "cl-labels", "flet", "labels", "macrolet", "symbol-macrolet", "dlet", "loop", "binding",
                  "with-open", "dotimes", "dolist", "do", "receive", "multiple-value-bind", "destructuring-bind"}
_CLAUSE_FORMS = {"cond", "case", "ecase", "ccase", "typecase", "etypecase", "cl-case", "cl-ecase",
                 "cl-typecase", "pcase", "pcase-exhaustive", "condition-case", "handler-case", "match",
                 "syntax-rules", "guard"}


def _head(node):
    if node.kind == "list" and node.items and node.items[0].kind == "atom":
        return node.items[0].text
    return None


def _defined_name(node, lang):
    """(name, kind) when node is a definition form, else None."""

    head = _head(node)
    definers = _DEFINERS.get(lang, {})
    if head not in definers or len(node.items) < 2:
        return None
    target = node.items[1]
    if target.kind == "list" and head in ("define-module", "defpackage", "define-library", "library"):
        return " ".join(item.text for item in target.items if item.kind == "atom"), "module"
    if target.kind == "list" and lang == "scheme" and target.items:
        # (define (name args) body)  /  (define ((curried a) b) ...)
        while target.kind == "list" and target.items:
            target = target.items[0]
    if target.kind != "atom":
        return None
    name = target.text.lstrip("'")
    if lang == "common-lisp":
        name = name.removeprefix("#:").lstrip(":")  # (defpackage :tool) / #:tool
    kind = definers[head]
    if lang == "scheme" and head == "define" and node.items[1].kind == "atom":
        value = node.items[2] if len(node.items) > 2 else None
        kind = "function" if value is not None and _head(value) in ("lambda", "lambda*", "case-lambda") else "variable"
    if lang == "common-lisp" and head == "defmethod":
        kind = "method"
    return name, kind


@dataclass
class Definition:
    name: str
    kind: str
    line: int
    end: int
    form: Node


def definitions(forms, lang):
    """Every definition, also inside progn, eval-when, with-eval-after-load and the like."""

    out = []

    def walk(node, depth=0):
        if node.kind != "list" or node.quoted:
            return
        found = _defined_name(node, lang)
        if found:
            out.append(Definition(found[0], found[1], node.line, node.end, node))
            if found[1] in ("function", "method"):
                return
        if depth < 4:
            for child in node.items:
                walk(child, depth + 1)

    for form in forms:
        walk(form)
    return out


def calls_in(node, lang, skip=frozenset()):
    """[(name, line)] for every evaluated list head inside node (definitions' bodies).

    Nested forms whose id is in skip (other functions' definitions) are not entered.
    """

    out = []

    def walk(item, skip_head=False):
        if item.kind == "list" and id(item) in skip and item is not node:
            return
        if item.kind == "list" and item.quoted:
            for child in item.items:  # quoted data may hold unquoted code: `(a ,(f x))
                if child.kind == "list":
                    walk(child)
            return
        if item.kind != "list" or item.quoted:
            if item.kind == "atom" and item.text.startswith("#'"):
                out.append((item.text[2:], item.line))
            return
        head = _head(item)
        children = item.items
        if head and not skip_head:
            out.append((head, item.items[0].line))
        start = 1 if head else 0
        if head in _ARGLIST_FORMS or (head and head in _DEFINERS.get(lang, {})):
            start = 2  # name or argument list
            if head in ("defun", "defmacro", "cl-defun", "cl-defmacro", "defsubst", "defn", "defn-",
                        "defmethod", "cl-defmethod", "define*") and len(children) > 2:
                start = 3 if head not in ("defn", "defn-") else 2
        if head in _BINDING_FORMS and len(children) > 1:
            bindings = children[1]
            if bindings.kind == "list":
                for binding in bindings.items:
                    if binding.kind == "list":
                        for value in binding.items[1:]:
                            walk(value)
            start = 2
        if head in _CLAUSE_FORMS:
            for clause in children[1:]:
                if clause.kind == "list":
                    for part in clause.items:
                        walk(part)
                else:
                    walk(clause)
            return
        for child in children[start:]:
            walk(child)

    if node.kind == "list":
        walk(node, skip_head=True)
    return out


def imports(forms, lang):
    """[(name, kind, line)]: kind is "require", "module" or "load"."""

    out = []

    def literal(node):
        if node.kind == "string":
            return node.text
        if node.kind == "atom":
            return node.text.lstrip("':")
        if node.kind == "list":
            return " ".join(item.text for item in node.items if item.kind == "atom")  # as written: (ice-9 popen)
        return None

    def walk(node, depth=0):
        if node.kind != "list" or depth > 6:
            return
        head = _head(node)
        args = node.items[1:]
        if head in ("require", "load", "load-file", "autoload", "use-modules", "use-module", "import",
                    "ql:quickload", "asdf:load-system"):
            if head == "autoload" and len(args) >= 2:
                name = literal(args[1])
                if name:
                    out.append((name, "require", node.line))
            elif head in ("use-modules", "use-module", "import"):
                for arg in args:
                    if arg.kind == "list" and arg.items and arg.items[0].kind == "list":
                        arg = arg.items[0]  # ((ice-9 popen) #:select (...))
                    name = literal(arg)
                    if name:
                        out.append((name, "module", node.line))
            elif args:
                name = literal(args[0])
                if name:
                    out.append((name, "load" if head in ("load", "load-file") else "require", node.line))
        elif head == "define-module":
            items = node.items
            for index, item in enumerate(items):
                if item.kind == "atom" and item.text == "#:use-module" and index + 1 < len(items):
                    name = literal(items[index + 1])
                    if name:
                        out.append((name, "module", item.line))
        elif head == "ns" and lang == "clojure":
            for clause in args:
                if clause.kind == "list" and _head(clause) in (":require", ":use", ":import"):
                    for spec in clause.items[1:]:
                        target = spec.items[0] if spec.kind == "list" and spec.items else spec
                        if target.kind == "atom":
                            out.append((target.text, "module", target.line))
        for child in node.items:
            walk(child, depth + 1)

    for form in forms:
        walk(form)
    return out


# -- resolving what is loaded ---------------------------------------------------

_INDEX = {}


def _elisp_index():
    if "elisp" in _INDEX:
        return _INDEX["elisp"]
    roots = sorted(Path("/usr/share/emacs").glob("*/lisp")) + [Path("/usr/share/emacs/site-lisp")]
    home = Path.home()
    roots += [home / ".config/emacs/elpa", home / ".emacs.d/elpa", home / ".config/emacs/lisp", home / ".emacs.d/lisp"]
    index = {}
    for root in roots:
        if not root.is_dir():
            continue
        for folder, _dirs, files in os.walk(root):
            for name in files:
                if name.endswith((".el", ".el.gz")) and not name.endswith("-autoloads.el"):
                    stem = name[:-6] if name.endswith(".el.gz") else name[:-3]
                    path = Path(folder) / name
                    if stem not in index or (index[stem].name.endswith(".gz") and not name.endswith(".gz")):
                        index[stem] = path
    _INDEX["elisp"] = index
    return index


def _guile_roots():
    roots = sorted(Path("/usr/share/guile").glob("[0-9]*")) + sorted(Path("/usr/share/guile/site").glob("[0-9]*"))
    roots += [Path("/usr/share/guile/site")]
    return [root for root in roots if root.is_dir()]


def resolve(name, kind, lang, here):
    """Local path for a loaded library, module or file, or None."""

    here = Path(here).parent
    if kind == "load":
        for candidate in (here / name, here / f"{name}.el", here / f"{name}.scm", here / f"{name}.lisp"):
            if candidate.is_file():
                return candidate
        return None
    if lang == "elisp":
        local = here / f"{name}.el"
        return local if local.is_file() else _elisp_index().get(name)
    if lang == "scheme":
        relative = name.replace(" ", "/")
        for root in [here] + _guile_roots():
            for suffix in (".scm", ".sls", ".sld"):
                candidate = root / f"{relative}{suffix}"
                if candidate.is_file():
                    return candidate
        return None
    if lang == "clojure":
        relative = name.replace(".", "/").replace("-", "_")
        for suffix in (".clj", ".cljc"):
            candidate = here / f"{relative}{suffix}"
            if candidate.is_file():
                return candidate
    return None


# -- one file ------------------------------------------------------------------

@dataclass
class LispFile:
    path: Path
    lang: str
    lines: list
    forms: list
    defs: list


def read(path):
    """LispFile for a path, or None when it is not Lisp or cannot be read."""

    path = Path(path)
    try:
        text = read_text(path)
    except (OSError, EOFError, gzip.BadGzipFile):
        return None
    first = text.split("\n", 1)[0]
    lang = dialect(path, first)
    if lang is None:
        return None
    body = text
    if first.startswith("#!"):
        body = "\n" + text.split("\n", 1)[1] if "\n" in text else ""
    forms = parse(body, lang)
    return LispFile(path, lang, text.splitlines(), forms, definitions(forms, lang))


class LispAnalyzer(Analyzer):
    """Emacs Lisp, Scheme, Common Lisp and Clojure through an S-expression reader."""

    name = "lisp"
    kinds = ("lisp",)

    def symbols(self, path):
        found = read(path)
        if found is None:
            return []
        return [
            Symbol(d.name, d.kind, str(found.path), d.line, None,
                   {"end_line": d.end, "dialect": DIALECT_NAMES.get(found.lang, found.lang)})
            for d in found.defs
        ]

    def edges(self, path):
        found = read(path)
        if found is None:
            return []
        out = []
        for name, kind, _line in imports(found.forms, found.lang):
            target = resolve(name, kind, found.lang, found.path)
            out.append(Edge(str(found.path), str(target) if target else None, "imports",
                            "resolved" if target else "unresolved", name=name))
        return out


if "lisp" not in registry.names():
    registry.register(LispAnalyzer())


def call_graph(path):
    """(LispFile, {caller: {callee: [lines]}}, {caller: {other: [lines]}}) or None.

    Callers are the file's functions and "(top level)". Calls to functions the
    file defines are function -> function edges; the rest (other libraries'
    functions, macros, special forms) are listed separately.
    """

    from collections import defaultdict

    found = read(path)
    if found is None:
        return None
    functions = [d for d in found.defs if d.kind in ("function", "method")]
    own = {d.name for d in functions}
    bodies = {id(d.form) for d in functions}
    inner = defaultdict(lambda: defaultdict(list))
    outer = defaultdict(lambda: defaultdict(list))

    def record(caller, pairs):
        for name, line in pairs:
            if name:
                (inner if name in own else outer)[caller][name].append(line)

    for definition in functions:
        record(definition.name, calls_in(definition.form, found.lang, skip=bodies))
    for form in found.forms:
        if form.kind != "list" or form.quoted or id(form) in bodies:
            continue
        head = _head(form)
        record("(top level)", ([(head, form.line)] if head else []) + calls_in(form, found.lang, skip=bodies))

    def clean(table):
        return {k: {n: sorted(set(v)) for n, v in d.items()} for k, d in table.items()}

    return found, clean(inner), clean(outer)
