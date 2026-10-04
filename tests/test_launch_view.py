import os
import subprocess
import sys
from pathlib import Path

import pytest

from xray.launchgraph import launch_lines

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


def run_xray(cwd, site, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO), str(site)])

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_launch_lines_lists_edges(tmp_path, installed):
    command = write(
        tmp_path / "bin" / "toolz",
        "#!/usr/bin/env python3\nfrom libz.core import main\n",
    )

    lines = launch_lines(command)

    assert lines == [
        f"{command.resolve()} -> {(installed / 'libz' / 'core.py').resolve()}"
    ]


def test_launch_lines_without_launcher_code(tmp_path):
    command = write(
        tmp_path / "bin" / "toolz",
        "#!/usr/bin/env python3\nimport os\n",
    )

    assert launch_lines(command) == ["No launcher code found"]


def test_launch_lines_for_shell_command(tmp_path):
    command = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    assert launch_lines(command) == ["No launcher code found"]


def test_cli_launch_shows_installed_file(tmp_path, installed):
    command = write(
        tmp_path / "bin" / "toolz",
        "#!/usr/bin/env python3\nfrom libz.core import main\n",
    )

    result = run_xray(tmp_path, installed, str(command), "--launch")

    assert result.returncode == 0
    assert "Launcher code of" in result.stdout
    assert str((installed / "libz" / "core.py").resolve()) in result.stdout


def test_cli_launch_on_shell_command(tmp_path, installed):
    command = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(tmp_path, installed, str(command), "--launch")

    assert result.returncode == 0
    assert "No launcher code found" in result.stdout


def test_help_mentions_launch(tmp_path, installed):
    result = run_xray(tmp_path, installed, "--help")

    assert "--launch" in result.stdout
