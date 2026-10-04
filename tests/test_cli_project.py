import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

PROJECT_OPTIONS = [
    "--callgraph",
    "--unused-symbols",
    "--coupling",
    "--call-coupling",
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


def make_project(tmp_path):
    write(
        tmp_path / "utils.py",
        "def calculate():\n    return 1\n\n\ndef orphan():\n    return 2\n",
    )

    return write(
        tmp_path / "main.py",
        "from utils import calculate\n"
        "\n"
        "\n"
        "def main():\n"
        "    calculate()\n",
    )


def test_callgraph_option(tmp_path):
    main = make_project(tmp_path)

    result = run_xray(tmp_path, str(main), "--callgraph")

    assert result.returncode == 0, result.stderr
    assert "Call graph of main.py" in result.stdout
    assert "main.py:main" in result.stdout


def test_unused_symbols_option(tmp_path):
    main = make_project(tmp_path)

    result = run_xray(tmp_path, str(main), "--unused-symbols")

    assert result.returncode == 0, result.stderr
    assert "Unused symbols in" in result.stdout
    assert "orphan" in result.stdout


def test_coupling_option(tmp_path):
    main = make_project(tmp_path)

    result = run_xray(tmp_path, str(main), "--coupling")

    assert result.returncode == 0, result.stderr
    assert "Module coupling" in result.stdout
    assert "This file: main.py:" in result.stdout


def test_call_coupling_option(tmp_path):
    main = make_project(tmp_path)

    result = run_xray(tmp_path, str(main), "--call-coupling")

    assert result.returncode == 0, result.stderr
    assert "Call coupling" in result.stdout
    assert "- main.py: calls out" in result.stdout


@pytest.mark.parametrize("option", PROJECT_OPTIONS)
def test_project_option_rejects_shell_script(tmp_path, option):
    script = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(tmp_path, str(script), option)

    assert result.returncode == 3
    assert "Not a Python file" in result.stderr
    assert result.stdout == ""


def test_extra_argument_is_rejected(tmp_path):
    main = make_project(tmp_path)

    result = run_xray(tmp_path, str(main), "--callgraph", "extra")

    assert result.returncode == 2
