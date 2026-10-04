from pathlib import Path

import xray.calls as calls_module
from xray.locate import locate


def make(path, text="#!/bin/sh\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)

    return path


def test_finds_a_command_on_path(tmp_path, monkeypatch):
    tool = make(tmp_path / "bin" / "locq")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))

    assert locate("locq") == tool.resolve()


def test_accepts_a_path_with_a_slash(tmp_path):
    tool = make(tmp_path / "locq")

    assert locate(str(tool)) == tool.resolve()


def test_missing_command_gives_none(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    assert locate("locq_missing") is None
    assert locate(str(tmp_path / "nothing")) is None


def test_bare_names_ignore_the_current_directory(tmp_path, monkeypatch):
    make(tmp_path / "locq")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    assert locate("locq") is None


def test_calls_still_exposes_locate():
    assert calls_module._locate is locate
