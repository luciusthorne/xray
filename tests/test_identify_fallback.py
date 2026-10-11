import os
import subprocess
import sys
from pathlib import Path

import xray.identify as identify_module
from xray.identify import FALLBACK, identify_file

REPO = Path(__file__).resolve().parent.parent


def test_missing_file_command_gives_the_fallback(tmp_path, monkeypatch):
    def run(command, **kwargs):
        raise FileNotFoundError("file")

    monkeypatch.setattr(identify_module.subprocess, "run", run)

    assert identify_file(tmp_path) == FALLBACK
    assert not FALLBACK.startswith("Python")


def test_normal_output_is_unchanged(tmp_path, monkeypatch):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, "ASCII text\n", "")

    monkeypatch.setattr(identify_module.subprocess, "run", run)

    assert identify_file(tmp_path) == "ASCII text"


def test_cli_works_without_the_file_command(tmp_path):
    tool = tmp_path / "tool"
    tool.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    tool.chmod(0o755)

    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    env["PATH"] = str(tmp_path / "empty")

    result = subprocess.run(
        [sys.executable, "-m", "xray.cli", str(tool)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert FALLBACK in result.stdout
    assert "Traceback" not in result.stderr
