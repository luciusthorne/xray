import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from xray.overview import overview_lines

REPO = Path(__file__).resolve().parent.parent


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


@pytest.fixture
def installed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "libz" / "__init__.py")
    write(site / "libz" / "core.py", "def main():\n    pass\n")
    monkeypatch.syspath_prepend(str(site))

    return site


def test_shell_script_lists_what_it_runs(tmp_path):
    script = write(
        tmp_path / "tool",
        "#!/bin/sh\nnosuchcmd_xyz\n",
    )

    lines = overview_lines(script)

    assert "Commands:" in lines
    assert "- nosuchcmd_xyz -> not found" in lines


@pytest.mark.skipif(
    shutil.which("readelf") is None, reason="readelf not installed"
)
def test_elf_binary_lists_libraries():
    binary = Path(shutil.which("sh")).resolve()

    assert "Libraries:" in overview_lines(binary)


def test_python_launcher_lists_installed_code(tmp_path, installed):
    command = write(
        tmp_path / "bin" / "toolz",
        "#!/usr/bin/env python3\nfrom libz.core import main\n",
    )

    lines = overview_lines(command)

    assert lines[0] == "Launcher code:"
    assert any(
        str((installed / "libz" / "core.py").resolve()) in line
        for line in lines
    )


def test_python_project_file_has_no_overview(tmp_path):
    source = write(tmp_path / "a.py", "import os\n")

    assert overview_lines(source) == []


def test_unknown_file_has_no_overview(tmp_path):
    other = write(tmp_path / "notes.txt", "plain text\n")

    assert overview_lines(other) == []


def test_cli_shows_overview_for_shell_script(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\nnosuchcmd_xyz\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    result = subprocess.run(
        [sys.executable, "-m", "xray", str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Overview" in result.stdout
    assert "nosuchcmd_xyz" in result.stdout


def test_cli_has_no_overview_for_python_file(tmp_path):
    source = write(tmp_path / "a.py", "import os\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    result = subprocess.run(
        [sys.executable, "-m", "xray", str(source)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Overview" not in result.stdout


def test_shell_script_without_visible_commands_gets_a_note(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    lines = overview_lines(script)

    assert lines[-1].startswith("Note: no external commands found")


def test_shell_script_with_commands_has_no_note(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\nnosuchcmd_xyz\n")

    assert not any(
        line.startswith("Note:") for line in overview_lines(script)
    )
