import os
import subprocess
import sys
from pathlib import Path

import xray.command_analyzers as analyzers_module
from xray.chain import chain_lines
from xray.elfscan import ElfScan

REPO = Path(__file__).resolve().parent.parent


def write(path, text, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")

    path.chmod(mode)

    return path


def sh(path, body="echo hi\n"):
    return write(path, "#!/bin/sh\n" + body)


def test_shell_chain(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "chainb", "chainc\n")
    c = sh(bindir / "chainc")
    tool = sh(tmp_path / "tool", "chainb\n")
    monkeypatch.setenv("PATH", str(bindir))

    assert chain_lines(tool) == [
        f"{tool.resolve()} [shell]",
        f"└── chainb -> {b.resolve()} [shell]",
        f"    └── chainc -> {c.resolve()} [shell]",
    ]


def test_command_not_found(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    tool = sh(tmp_path / "tool", "chainzz\n")

    assert chain_lines(tool) == [
        f"{tool.resolve()} [shell]",
        "└── chainzz (not found)",
    ]


def test_depth_limit(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "chainb", "chainc\n")
    sh(bindir / "chainc")
    tool = sh(tmp_path / "tool", "chainb\n")
    monkeypatch.setenv("PATH", str(bindir))

    assert chain_lines(tool, max_depth=1) == [
        f"{tool.resolve()} [shell]",
        f"└── chainb -> {b.resolve()} [shell]",
        "Truncated: depth limit (1) reached",
    ]


def test_cycles_terminate(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    a = sh(bindir / "chaina", "chainb\n")
    b = sh(bindir / "chainb", "chaina\n")
    tool = sh(tmp_path / "tool", "chaina\n")
    monkeypatch.setenv("PATH", str(bindir))

    assert chain_lines(tool, max_depth=10) == [
        f"{tool.resolve()} [shell]",
        f"└── chaina -> {a.resolve()} [shell]",
        f"    └── chainb -> {b.resolve()} [shell]",
        f"        └── chaina -> {a.resolve()} [shell] (seen)",
    ]


def test_file_limit_is_reported(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"

    for name in ("chaina", "chainb", "chainc"):
        sh(bindir / name)

    tool = sh(tmp_path / "tool", "chaina\nchainb\nchainc\n")
    monkeypatch.setenv("PATH", str(bindir))

    lines = chain_lines(tool, max_files=2)

    assert len(lines) == 3
    assert lines[-1] == "Truncated: file limit (2) reached"


def test_elf_libraries_are_leaves(tmp_path, monkeypatch):
    lib = write(tmp_path / "libs" / "libfoo.so.1", "", mode=0o644)
    binary = write(tmp_path / "prog", b"\x7fELF" + bytes(60))

    monkeypatch.setattr(
        analyzers_module,
        "scan_elf",
        lambda path: ElfScan(needed=("libfoo.so.1", "libgone.so.1")),
    )
    monkeypatch.setattr(
        analyzers_module,
        "ldconfig_cache",
        lambda: {"libfoo.so.1": str(lib)},
    )

    assert chain_lines(binary) == [
        f"{binary.resolve()} [elf]",
        f"├── libfoo.so.1 -> {lib.resolve()} [library]",
        "└── libgone.so.1 (not found)",
    ]


def test_python_command_is_a_single_line(tmp_path):
    tool = write(tmp_path / "tool", "#!/usr/bin/env python3\nimport os\n")

    assert chain_lines(tool) == [f"{tool.resolve()} [python]"]


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


def test_cli_chain(tmp_path):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "chainb")
    tool = sh(tmp_path / "tool", "chainb\n")

    result = run_xray(tmp_path, bindir, str(tool), "--chain")

    assert result.returncode == 0
    assert "Chain of tool" in result.stdout
    assert f"chainb -> {b.resolve()} [shell]" in result.stdout


def test_help_mentions_chain(tmp_path):
    result = run_xray(tmp_path, tmp_path, "--help")

    assert "--chain" in result.stdout
