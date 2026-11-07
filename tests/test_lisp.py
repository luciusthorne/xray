"""Lisp family: an exact S-expression reader for Emacs Lisp, Scheme, Common Lisp and Clojure."""

import gzip
import subprocess
import sys
from pathlib import Path

from xray import lisp
from xray.entrypoints import command_kind
from xray.scriptgraph import callgraph_lines, lisp_graph

REPO = Path(__file__).resolve().parents[1]

ELISP = """;;; tool.el --- test  -*- lexical-binding: t -*-
(require 'helper-lib)

(defun tool--paren-char ()
  "A docstring with (not-a-call) and ) inside."
  (list ?\\( ?\\) ?( ?) #'tool--helper))

(defun tool--helper (x)
  (let ((tool--paren-char 1)          ; a binding, not a call
        (y (tool--compute x)))
    (cond ((tool--compute y) 'done)    ; clause test is a call
          (t '(tool--quoted data)))))  ; quoted data is not

(defun tool--compute (n)
  `(result ,(tool--paren-char) ,@n))   ; only the unquoted part is code

#| a block comment with (tool--helper) |#
#;(tool--helper 'ignored)
(tool--helper 3)
(call-process "notify-send" nil nil nil "hi")
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_kinds(tmp_path):
    assert command_kind(_write(tmp_path, "a.el", '(message "hi")\n')) == "lisp"
    assert command_kind(_write(tmp_path, "a.scm", "(display 1)\n")) == "lisp"
    assert command_kind(_write(tmp_path, "a.clj", "(ns a)\n")) == "lisp"
    guile = _write(tmp_path, "tool", "#!/usr/bin/guile -s\n!#\n(display 1)\n")
    assert command_kind(guile) == "lisp" and lisp.read(guile).lang == "scheme"
    packed = tmp_path / "b.el.gz"
    packed.write_bytes(gzip.compress(b"(defun b () 1)\n"))
    assert command_kind(packed) == "lisp"
    assert [d.name for d in lisp.read(packed).defs] == ["b"]


def test_emacs_lisp_definitions_calls_and_traps(tmp_path):
    path = _write(tmp_path, "tool.el", ELISP)
    found = lisp.read(path)
    spans = {d.name: (d.line, d.end) for d in found.defs}
    assert spans == {"tool--paren-char": (4, 6), "tool--helper": (8, 12), "tool--compute": (14, 15)}

    _source, inner, outer = lisp.call_graph(path)
    assert inner["tool--paren-char"] == {"tool--helper": [6]}         # #'name is a reference
    assert inner["tool--helper"] == {"tool--compute": [10, 11]}       # not the let binding, not quoted data
    assert inner["tool--compute"] == {"tool--paren-char": [15]}       # unquoted inside a backquote
    assert inner["(top level)"] == {"tool--helper": [19]}             # not the block or datum comment
    assert "call-process" in outer["(top level)"]
    assert lisp.imports(found.forms, found.lang) == [("helper-lib", "require", 2)]


def test_other_dialects(tmp_path):
    scheme = lisp.read(_write(tmp_path, "m.scm", """(define-module (my tool) #:use-module (ice-9 popen))
(define (helper x) (* x 2))
(define answer 42)
(define run (lambda () (helper answer)))
(use-modules ((srfi srfi-1) #:select (fold)))
"""))
    kinds = {d.name: d.kind for d in scheme.defs}
    assert kinds == {"my tool": "module", "helper": "function", "answer": "variable", "run": "function"}
    assert [(n, k) for n, k, _ in lisp.imports(scheme.forms, scheme.lang)] == [
        ("ice-9 popen", "module"), ("srfi srfi-1", "module")]

    cl = lisp.read(_write(tmp_path, "c.lisp", "(defpackage :tool (:use :cl))\n(defmethod area ((s square)) (* (side s) (side s)))\n(defun main () (area (make-square)))\n"))
    assert {d.name: d.kind for d in cl.defs} == {"tool": "module", "area": "method", "main": "function"}

    clj = lisp.read(_write(tmp_path, "c.clj", "(ns app.core (:require [clojure.string :as str]))\n(defn greet [n] (str/upper-case n))\n(defn -main [] (greet \"x\"))\n"))
    assert {d.name for d in clj.defs} == {"app.core", "greet", "-main"}
    assert ("clojure.string", "module") in [(n, k) for n, k, _ in lisp.imports(clj.forms, clj.lang)]


def test_local_require_resolves(tmp_path):
    _write(tmp_path, "helper-lib.el", "(provide 'helper-lib)\n")
    path = _write(tmp_path, "tool.el", ELISP)
    edges = lisp.LispAnalyzer().edges(path)
    assert edges[0].status == "resolved" and edges[0].target.endswith("helper-lib.el")


def test_callgraph_view_and_cli(tmp_path):
    path = _write(tmp_path, "tool.el", ELISP)
    text = "\n".join(callgraph_lines(lisp_graph(path), "tool.el", "tool--compute"))
    assert "← tool--helper  (lines 10, 11)" in text
    result = subprocess.run([sys.executable, "-m", "xray.cli", str(path), "--callgraph"],
                            cwd=REPO, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "→ tool--compute" in result.stdout
    code = subprocess.run([sys.executable, "-m", "xray.cli", str(path), "--code", "tool--compute"],
                          cwd=REPO, capture_output=True, text=True, check=False)
    assert "(defun tool--compute (n)" in code.stdout and "result" in code.stdout


def test_evidence_graph_follows_requires_and_program_starts(tmp_path):
    from xray.evidence import build_evidence_graph

    _write(tmp_path, "helper-lib.el", "(provide 'helper-lib)\n")
    path = _write(tmp_path, "tool.el", ELISP)
    graph = build_evidence_graph(path, max_depth=1)
    kinds = {(link.kind, link.target.rsplit("/", 1)[-1]) for link in graph.outgoing(str(path.resolve()))}
    assert ("imports", "helper-lib.el") in kinds
    assert ("runs", "command:notify-send") in kinds or any(k == "runs" for k, _ in kinds)
