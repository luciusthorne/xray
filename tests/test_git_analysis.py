import os
import subprocess
import sys
from pathlib import Path

import pytest

from xray.git_analysis import FileChange, _parse_name_status, changes_since

REPO = Path(__file__).resolve().parent.parent


def git(cwd, *args):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )


def make_repo(root):
    git(root, "init", "-q")
    git(root, "config", "user.email", "xray-tests@example.invalid")
    git(root, "config", "user.name", "XRAY tests")
    (root / "main.py").write_text("import helper\n", encoding="utf-8")
    (root / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "staged.py").write_text("VALUE = 1\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "baseline")


def test_name_status_parser_preserves_rename_paths():
    assert _parse_name_status("R100\0old name.py\0new name.py\0") == [
        FileChange("R100", "new name.py", "old name.py")
    ]


def test_changes_since_includes_staged_unstaged_untracked_and_impact(tmp_path):
    make_repo(tmp_path)
    (tmp_path / "helper.py").write_text("VALUE = 2\n", encoding="utf-8")
    (tmp_path / "staged.py").write_text("VALUE = 2\n", encoding="utf-8")
    git(tmp_path, "add", "staged.py")
    (tmp_path / "new.py").write_text("VALUE = 3\n", encoding="utf-8")

    root, changes = changes_since(tmp_path / "main.py")

    assert root == tmp_path.resolve()
    assert {(change.status, change.path) for change in changes} == {
        ("M", "helper.py"),
        ("M", "staged.py"),
        ("??", "new.py"),
    }

    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    result = subprocess.run(
        [sys.executable, "-m", "xray", str(tmp_path / "main.py"), "--changes"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "??  new.py" in result.stdout
    assert "Affected project files" in result.stdout
    assert "main.py (depends on helper.py)" in result.stdout


def test_changes_since_supports_an_explicit_base(tmp_path):
    make_repo(tmp_path)
    base = git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    (tmp_path / "helper.py").write_text("VALUE = 2\n", encoding="utf-8")

    _root, changes = changes_since(tmp_path / "main.py", base)

    assert [(change.status, change.path) for change in changes] == [
        ("M", "helper.py")
    ]


def test_changes_since_rejects_invalid_base_and_non_git_target(tmp_path):
    make_repo(tmp_path)
    with pytest.raises(ValueError, match="does not resolve"):
        changes_since(tmp_path / "main.py", "missing-ref")
    with pytest.raises(ValueError, match="not inside a Git worktree"):
        changes_since(tmp_path.parent / "outside.py")
