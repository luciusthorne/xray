import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

PYTHON_ONLY = [
    "--symbols",
    "--references",
    "--relationships",
    "--unused",
    "--complexity",
]


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def run_xray(cwd, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_symbols_option(tmp_path):
    source = write(tmp_path / "a.py", "def hello():\n    pass\n")

    result = run_xray(tmp_path, str(source), "--symbols")

    assert result.returncode == 0, result.stderr
    assert "Symbols in a.py" in result.stdout
    assert "- function: hello (line 1)" in result.stdout


def test_unused_option(tmp_path):
    source = write(tmp_path / "a.py", "import json\n")

    result = run_xray(tmp_path, str(source), "--unused")

    assert result.returncode == 0, result.stderr
    assert "Unused imports in a.py" in result.stdout
    assert "- json (line 1)" in result.stdout


def test_complexity_option(tmp_path):
    source = write(
        tmp_path / "a.py",
        "def f(x):\n    if x:\n        return 1\n    return 2\n",
    )

    result = run_xray(tmp_path, str(source), "--complexity")

    assert result.returncode == 0, result.stderr
    assert "Complexity of a.py" in result.stdout
    assert "Maximum complexity:" in result.stdout


def test_references_option(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "from utils import calculate\n\ncalculate()\n",
    )

    result = run_xray(tmp_path, str(main), "--references")

    assert result.returncode == 0, result.stderr
    assert "References in main.py" in result.stdout
    assert "calculate" in result.stdout


def test_relationships_option(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "from utils import calculate\n"
        "\n"
        "\n"
        "def main():\n"
        "    calculate()\n",
    )

    result = run_xray(tmp_path, str(main), "--relationships")

    assert result.returncode == 0, result.stderr
    assert "Relationships in main.py" in result.stdout
    assert "- calls: main -> calculate" in result.stdout


@pytest.mark.parametrize("option", PYTHON_ONLY)
def test_python_only_option_rejects_shell_script(tmp_path, option):
    script = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(tmp_path, str(script), option)

    assert result.returncode == 3
    assert "Not a Python file" in result.stderr
    assert result.stdout == ""


def test_extra_argument_is_rejected(tmp_path):
    source = write(tmp_path / "a.py", "x = 1\n")

    result = run_xray(tmp_path, str(source), "--symbols", "extra")

    assert result.returncode == 2
