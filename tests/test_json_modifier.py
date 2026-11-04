import json
import os
import subprocess
import sys
from pathlib import Path

from xray.textjson import text_to_data

REPO = Path(__file__).resolve().parent.parent


def run_xray(*args, cwd=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        env=env, cwd=cwd, capture_output=True, text=True, check=False,
    )


def script(tmp_path):
    path = tmp_path / "tool.sh"
    path.write_text("#!/bin/sh\nhelper() { :; }\nsort f | uniq\n", encoding="utf-8")
    path.chmod(0o755)

    return path


def test_text_layout_becomes_sections():
    data = text_to_data(
        [
            "XRAY", "────────────────────────────", "",
            "Report of tool", "════════════════════════════",
            "Identity", "────────",
            "Path: /usr/bin/tool", "Kind: shell",
            "",
            "Overview", "────────",
            "Commands:", "- sort", "- uniq",
            "- loose item",
            "Free text line",
        ],
        "--report", "tool",
    )

    assert data["schema_version"] == 1
    assert data["title"] == "Report of tool"
    identity, overview = data["sections"]
    assert identity["heading"] == "Identity"
    assert identity["fields"] == {"Path": "/usr/bin/tool", "Kind": "shell"}
    assert overview["fields"]["Commands"] == ["sort", "uniq", "loose item"]
    assert overview["lines"] == ["Free text line"]


def test_calls_json_lists_commands(tmp_path):
    result = run_xray(str(script(tmp_path)), "--calls", "--json")

    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["query"] == "--calls"
    commands = data["sections"][0]["fields"]["Commands"]
    assert any(item.startswith("sort") for item in commands)
    assert any(item.startswith("uniq") for item in commands)
    assert "XRAY" not in result.stdout.splitlines()[0]


def test_report_json_has_identity(tmp_path):
    result = run_xray(str(script(tmp_path)), "--report", "--json")

    assert result.returncode == 0, result.stderr
    sections = {s["heading"]: s for s in json.loads(result.stdout)["sections"]}
    assert sections["Identity"]["fields"]["Kind"] == "shell"


def test_json_cannot_follow_document_queries(tmp_path):
    for query in ("--html", "--graph-json", "--serve"):
        result = run_xray(str(script(tmp_path)), query, "--json")
        assert result.returncode == 2
        assert result.stdout == ""
        assert "cannot be combined with --json" in result.stderr


def test_json_and_markdown_are_exclusive(tmp_path):
    result = run_xray(str(script(tmp_path)), "--report", "--md", "--json")

    assert result.returncode == 2
    assert "--md and --json cannot be combined" in result.stderr


def test_errors_stay_on_stderr_with_json(tmp_path):
    result = run_xray(str(script(tmp_path)), "--complexity", "--json")

    assert result.returncode == 3
    assert result.stdout == ""
    assert result.stderr.startswith("Error:")


def test_plain_json_query_is_unchanged(tmp_path):
    result = run_xray(str(script(tmp_path)), "--json")

    assert result.returncode == 0, result.stderr
    assert "edges" in json.loads(result.stdout)
