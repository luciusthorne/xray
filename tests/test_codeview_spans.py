import shutil

import pytest

from xray.codeview import _brace_end, code_lines
from xray.treesitter_analyzers import parser_available

NEXT = "NEXT_DEFINITION_MARKER"


def shown(path, name):
    return "\n".join(code_lines(path, name))


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)

    return path


def test_shell_function_stops_at_its_closing_brace(tmp_path):
    path = write(
        tmp_path, "tool",
        "#!/bin/sh\n"
        "target() {\n"
        "  echo '}' \"{\"  # } in a comment\n"
        "  if true; then { echo nested; }; fi\n"
        "}\n"
        f"other() {{ echo {NEXT}; }}\n",
    )

    text = shown(path, "target")

    assert "echo nested" in text
    assert NEXT not in text
    assert "end of definition not found" not in text


def test_perl_sub_stops_at_its_closing_brace(tmp_path):
    path = write(
        tmp_path, "tool",
        "#!/usr/bin/perl\n"
        "sub target {\n"
        "    my %h = (a => '{');\n"
        "    return $#ARGV;\n"
        "}\n"
        f"sub other {{ print '{NEXT}'; }}\n",
    )

    text = shown(path, "target")

    assert "return $#ARGV;" in text
    assert NEXT not in text


@pytest.mark.skipif(not shutil.which("node"), reason="Node is required")
def test_javascript_function_uses_parser_end_line(tmp_path):
    path = write(
        tmp_path, "tool.js",
        "function target() {\n  return 1;\n}\n"
        f"function other() {{ return '{NEXT}'; }}\n",
    )

    text = shown(path, "target")

    assert "return 1;" in text
    assert NEXT not in text


@pytest.mark.skipif(not shutil.which("ruby"), reason="Ruby is required")
def test_ruby_method_uses_parser_end_line(tmp_path):
    path = write(
        tmp_path, "tool.rb",
        "def target\n  if true then 1 end\nend\n"
        f"def other\n  '{NEXT}'\nend\n",
    )

    text = shown(path, "target")

    assert "if true then 1 end" in text
    assert NEXT not in text


@pytest.mark.parametrize(
    ("language", "filename", "source"),
    [
        ("lua", "tool.lua", ("function target()\n  return 1\nend\n"
         f"function other() return '{NEXT}' end\n")),
        ("c", "tool.c", ("int target(void)\n{\n  return 1;\n}\n"
         f"int other(void) {{ return sizeof \"{NEXT}\"; }}\n")),
        ("typescript", "tool.ts", ("function target(): number {\n  return 1;\n}\n"
         f"function other(): string {{ return '{NEXT}'; }}\n")),
    ],
)
def test_tree_sitter_definitions_use_parser_end_line(tmp_path, language, filename, source):
    if not parser_available(language):
        pytest.skip(f"Neovim's {language} Tree-sitter parser is required")

    text = shown(write(tmp_path, filename, source), "target")

    assert "return 1" in text
    assert NEXT not in text


def test_unclosed_body_falls_back_to_a_labelled_excerpt():
    assert _brace_end(["f() {", "  echo"], 1) is None
    assert _brace_end(["f()", "", "", "echo"], 1) is None
