import shutil
import subprocess
from pathlib import Path

import pytest

import xray.provenance as provenance_module
from xray.provenance import package_of


def fake_run(returncode=0, stdout=""):
    def run(args, **kwargs):
        run.args = args

        return subprocess.CompletedProcess(args, returncode, stdout, "")

    return run


def test_returns_the_owning_package(tmp_path, monkeypatch):
    run = fake_run(0, "coreutils-9.10-5.fc44.x86_64\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert package_of(tmp_path) == "coreutils-9.10-5.fc44.x86_64"


def test_unowned_file_gives_none(tmp_path, monkeypatch):
    run = fake_run(1, "file /x is not owned by any package\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert package_of(tmp_path) is None


def test_missing_rpm_gives_none(tmp_path, monkeypatch):
    def run(args, **kwargs):
        raise FileNotFoundError("rpm")

    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert package_of(tmp_path) is None


def test_empty_output_gives_none(tmp_path, monkeypatch):
    run = fake_run(0, "\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert package_of(tmp_path) is None


def test_asks_rpm_about_the_resolved_path(tmp_path, monkeypatch):
    target = tmp_path / "real"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    run = fake_run(0, "pkg-1-1.noarch\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    package_of(link)

    assert run.args[0] == "rpm"
    assert run.args[-1] == str(target.resolve())


@pytest.mark.skipif(shutil.which("rpm") is None, reason="rpm not installed")
def test_real_system_owner_of_ls():
    ls = shutil.which("ls")

    assert package_of(Path(ls)).startswith("coreutils-")
