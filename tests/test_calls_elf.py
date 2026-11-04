import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import xray.calls as calls_module
import xray.command_analyzers as analyzer_module
from xray.calls import calls_lines
from xray.elfscan import ElfScan

REPO = Path(__file__).resolve().parent.parent


def fake_elf(tmp_path):
    path = tmp_path / "tool"
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


def run_xray(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_elf_lines(tmp_path, monkeypatch):
    lib = tmp_path / "libs" / "libfoo.so.1"
    lib.parent.mkdir()
    lib.write_text("", encoding="utf-8")

    scan = ElfScan(
        needed=("libfoo.so.1", "libgone.so.1"),
        interpreter="/lib64/ld-linux-x86-64.so.2",
        imports=("a", "b", "c"),
    )
    monkeypatch.setattr(calls_module, "scan_elf", lambda path: scan)
    monkeypatch.setattr(analyzer_module, "scan_elf", lambda path: scan)
    monkeypatch.setattr(analyzer_module, "ldconfig_cache", lambda: {"libfoo.so.1": str(lib)})

    assert calls_lines(fake_elf(tmp_path)) == [
        "Interpreter:",
        "- /lib64/ld-linux-x86-64.so.2",
        "Libraries:",
        f"- libfoo.so.1 -> {lib.resolve()}",
        "- libgone.so.1 -> not found",
        "Imports (3):",
        "- a",
        "- b",
        "- c",
    ]


def test_static_binary(tmp_path, monkeypatch):
    scan = ElfScan(imports=("x",))
    monkeypatch.setattr(calls_module, "scan_elf", lambda path: scan)
    monkeypatch.setattr(analyzer_module, "scan_elf", lambda path: scan)
    monkeypatch.setattr(analyzer_module, "ldconfig_cache", dict)

    assert calls_lines(fake_elf(tmp_path)) == [
        "Interpreter:",
        "none",
        "Libraries:",
        "none",
        "Imports (1):",
        "- x",
    ]


def test_imports_are_capped(tmp_path, monkeypatch):
    names = tuple(f"sym{i}" for i in range(5))
    scan = ElfScan(interpreter="/ld.so", imports=names)
    monkeypatch.setattr(calls_module, "scan_elf", lambda path: scan)
    monkeypatch.setattr(analyzer_module, "scan_elf", lambda path: scan)
    monkeypatch.setattr(analyzer_module, "ldconfig_cache", dict)

    lines = calls_lines(fake_elf(tmp_path), max_imports=2)

    assert lines[-4:] == [
        "Imports (5):",
        "- sym0",
        "- sym1",
        "- ... and 3 more",
    ]


def test_elf_without_readable_information(tmp_path, monkeypatch):
    monkeypatch.setattr(calls_module, "scan_elf", lambda path: ElfScan())

    assert calls_lines(fake_elf(tmp_path)) == [
        "No ELF information found (is readelf installed?)"
    ]


@pytest.mark.skipif(
    shutil.which("readelf") is None, reason="readelf not installed"
)
def test_cli_calls_on_a_real_binary():
    result = run_xray(sys.executable, "--calls")

    assert result.returncode == 0
    assert "Libraries:" in result.stdout
    assert "Imports (" in result.stdout


def test_help_describes_binaries():
    result = run_xray("--help")

    assert "script or binary" in result.stdout
