import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)

    return path


def run_xray(cwd, bindir, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_default_view_shows_the_owning_package(tmp_path):
    bindir = tmp_path / "fakebin"
    write(bindir / "rpm", "#!/bin/sh\necho fakepkg-1-1.noarch\n")
    tool = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(tmp_path, bindir, str(tool))

    assert result.returncode == 0
    assert "Package:    fakepkg-1-1.noarch" in result.stdout


def test_default_view_has_no_package_line_when_unowned(tmp_path):
    bindir = tmp_path / "fakebin"
    write(bindir / "rpm", "#!/bin/sh\nexit 1\n")
    tool = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(tmp_path, bindir, str(tool))

    assert result.returncode == 0
    assert "Package:" not in result.stdout
