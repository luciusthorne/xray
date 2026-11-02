import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from xray.browse import browse, function_names

REPO = Path(__file__).resolve().parent.parent


def script(tmp_path):
    path = tmp_path / "tool.sh"
    path.write_text(
        "#!/bin/sh\nfirst() {\n  echo one\n}\nsecond() {\n  sort f\n}\nfirst\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def drive(path, answers):
    answers = iter(answers)
    out = []

    def read(prompt):
        try:
            return next(answers)
        except StopIteration:
            raise EOFError from None

    browse(path, read=read, write=out.append)
    return "\n".join(out)


def test_functions_are_listed_and_code_is_shown(tmp_path):
    text = drive(script(tmp_path), ["2", "2", "b", "q"])

    assert "  1. first" in text
    assert "  2. second" in text
    assert "sort f" in text


def test_function_can_be_picked_by_name(tmp_path):
    text = drive(script(tmp_path), ["2", "first", "q"])

    assert "echo one" in text


def test_views_and_bad_choices(tmp_path):
    text = drive(script(tmp_path), ["9", "x", "3"])

    assert "Unknown choice: 9" in text
    assert "Unknown choice: x" in text
    assert "sort" in text  # the Calls view, then input ends


def test_python_function_names(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text("class A:\n    def run(self): pass\ndef helper(): pass\n", encoding="utf-8")

    assert function_names(path, "python") == ["A", "helper", "run"]


@pytest.mark.skipif(not Path("/usr/bin/ls").exists(), reason="needs /usr/bin/ls")
def test_elf_menu_offers_toolchain():
    text = drive(Path("/usr/bin/ls"), ["5", "q"])

    assert "5. Toolchain" in text
    assert "Language:" in text


def test_cli_refuses_without_a_terminal(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(REPO))
    result = subprocess.run(
        [sys.executable, "-m", "xray.cli", str(script(tmp_path)), "--browse"],
        env=env, input="", capture_output=True, text=True, check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "--browse needs an interactive terminal" in result.stderr


@pytest.mark.skipif(not shutil.which("script"), reason="util-linux script is required")
def test_cli_runs_in_a_pseudo_terminal(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(REPO))
    command = f"{sys.executable} -m xray.cli {script(tmp_path)} --browse"
    result = subprocess.run(
        ["script", "-qec", command, "/dev/null"],
        env=env, input="1\nq\n", capture_output=True, text=True, check=False, timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Identity" in result.stdout
