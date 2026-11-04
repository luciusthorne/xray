import json
import os
import re
import subprocess
import sys
from pathlib import Path

from xray.html import render_html

REPO = Path(__file__).resolve().parent.parent

DATA = {
    "root": "/x/tool",
    "nodes": [
        {"id": "/x/tool", "kind": "shell", "package": None, "symbol_count": 0}
    ],
    "edges": [],
    "metadata": {"truncated": False, "xray_version": "0.0.0"},
}


def embedded(page):
    match = re.search(
        r'<script id="graph-data" type="application/json">(.*?)</script>',
        page,
        re.DOTALL,
    )

    assert match is not None

    return json.loads(match.group(1))


def test_page_embeds_the_data():
    page = render_html(DATA)

    assert page.startswith("<!doctype html>")
    assert embedded(page) == DATA


def test_page_loads_nothing_from_the_network():
    page = render_html(DATA)

    # The SVG namespace is an identifier for createElementNS, not a URL.
    stripped = page.replace("http://www.w3.org/2000/svg", "")

    assert "http://" not in stripped
    assert "https://" not in stripped

    for loader in ("src=", "href=", "@import", "url(", "fetch(", "XMLHttpRequest"):
        assert loader not in page, loader


def test_script_tags_in_data_cannot_break_out():
    data = dict(DATA)
    data["root"] = "</script><script>alert(1)</script>"

    page = render_html(data)

    assert page.count("</script>") == 2
    assert embedded(page)["root"] == data["root"]


def test_page_title_names_the_root():
    assert "tool" in re.search(
        r"<title>(.*?)</title>", render_html(DATA)
    ).group(1)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)

    return path


def run_xray(cwd, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_html_prints_only_the_page(tmp_path):
    tool = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(tmp_path, str(tool), "--html")

    assert result.returncode == 0
    assert result.stdout.startswith("<!doctype html>")
    assert "XRAY\n" not in result.stdout.split("<")[0]
    assert embedded(result.stdout)["root"] == str(tool.resolve())


def test_cli_html_errors_go_to_stderr(tmp_path):
    result = run_xray(tmp_path, "missing_cmd_xyz", "--html")

    assert result.returncode == 3
    assert result.stdout == ""


def test_help_mentions_html(tmp_path):
    assert "--html" in run_xray(tmp_path, "--help").stdout
