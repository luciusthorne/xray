import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def run_module(cwd, *args):
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


def test_bad_option_exits_2(tmp_path):
    result = run_module(tmp_path, "--bad-option")

    assert result.returncode == 2
    assert "Unknown option" in result.stderr
    assert result.stdout == ""


def test_no_arguments_exits_2(tmp_path):
    result = run_module(tmp_path)

    assert result.returncode == 2
    assert result.stdout == ""


def test_missing_target_exits_3(tmp_path):
    result = run_module(tmp_path, "missing.py")

    assert result.returncode == 3
    assert "Command not found" in result.stderr


def test_success_exits_0(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("import os\n", encoding="utf-8")

    result = run_module(tmp_path, str(target))

    assert result.returncode == 0
    assert result.stderr == ""
