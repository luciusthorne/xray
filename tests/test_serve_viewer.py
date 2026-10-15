import json
import os
import shutil
import subprocess

import pytest

from xray.html import render_html

DATA = {"root": "/x/t", "nodes": [], "edges": [], "metadata": {}}
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


def between(page, start, end):
    return page.split(start)[1].split(end)[0]


def run_tokens(lang, lines):
    page = render_html(DATA, serve=True)
    code = between(page, "/* tokens:start */", "/* tokens:end */")
    script = (
        code
        + "\nvar st = {block: false};\n"
        + "var rows = JSON.parse(process.env.XLINES).map(function (l) {\n"
        + "  return tokens(l, SPEC[process.env.XLANG], st)"
        + ".filter(function (t) { return t[0]; });\n"
        + "});\n"
        + "console.log(JSON.stringify(rows));\n"
    )
    env = dict(os.environ, XLINES=json.dumps(lines), XLANG=lang)
    result = subprocess.run(
        [NODE, "-e", script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr

    return json.loads(result.stdout)


def test_serve_page_has_the_viewer_and_static_page_does_not():
    assert "viewer:start" in render_html(DATA, serve=True)
    assert "tk-kw" in render_html(DATA, serve=True)
    assert "viewer:start" not in render_html(DATA)
    assert "tk-kw" not in render_html(DATA)


def test_viewer_builds_text_only_and_loads_nothing():
    page = render_html(DATA, serve=True)
    block = between(page, "/* viewer:start */", "/* viewer:end */")

    assert "createTextNode" in block
    assert "textContent" in block

    for banned in ("innerHTML", "insertAdjacent", "document.write",
                   "fetch(", "import(", "src=", "http"):
        assert banned not in block, banned


def test_gutter_is_generated_content_that_cannot_be_selected():
    page = render_html(DATA, serve=True)

    assert "attr(data-n)" in page
    assert "user-select: none" in page


@needs_node
def test_c_tokens():
    rows = run_tokens("c", ["#include <x.h>", "int x = 0x1F; // hi"])

    assert rows == [
        [["pp", "#include <x.h>"]],
        [["kw", "int"], ["num", "0x1F"], ["com", "// hi"]],
    ]


@needs_node
def test_shell_tokens():
    rows = run_tokens("sh", ['echo "a b" # note', "echo $# x"])

    assert rows == [
        [["str", '"a b"'], ["com", "# note"]],
        [["var", "$#"]],
    ]


@needs_node
def test_block_comment_carries_across_lines():
    rows = run_tokens("c", ["/* a", "b */ int", "int y;"])

    assert rows == [
        [["com", "/* a"]],
        [["com", "b */"], ["kw", "int"]],
        [["kw", "int"]],
    ]
