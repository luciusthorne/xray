import os
import re
import subprocess
import sys
from pathlib import Path

import xray

REPO = Path(__file__).resolve().parent.parent


def run_xray(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray", *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_version_option():
    result = run_xray("--version")

    assert result.returncode == 0
    assert result.stdout == f"xray {xray.__version__}\n"
    assert result.stderr == ""


def test_short_version_option():
    result = run_xray("-V")

    assert result.returncode == 0
    assert result.stdout == f"xray {xray.__version__}\n"


def test_version_matches_pyproject():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)

    assert match is not None
    assert match.group(1) == xray.__version__


def test_help_documents_exit_codes():
    result = run_xray("--help")

    assert result.returncode == 0
    assert "Exit codes:" in result.stdout

    for line in (
        "  0  success",
        "  1  general error or unexpected crash",
        "  2  invalid command-line usage",
        "  3  target or file error",
        "  4  analysis error",
    ):
        assert line in result.stdout


def test_help_lists_version_option():
    result = run_xray("--help")

    assert "--version" in result.stdout
