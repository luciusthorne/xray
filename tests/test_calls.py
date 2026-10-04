import os
import subprocess
import sys
from pathlib import Path

from xray.calls import calls_lines

REPO = Path(__file__).resolve().parent.parent


def write(path, text, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")

    path.chmod(mode)

    return path


def make_bin(tmp_path):
    bindir = tmp_path / "fakebin"
    a = write(bindir / "fakeqa", "#!/usr/bin/env python3\nprint('a')\n")
    b = write(bindir / "fakeqb", "#!/bin/sh\necho b\n")

    return bindir, a, b


SCRIPT = (
    "#!/bin/sh\n"
    "helper() {\n"
    "  echo hi\n"
    "}\n"
    ". ./lib.sh\n"
    "fakeqa | fakeqb\n"
    "fakeqc\n"
)


def test_calls_lines_for_a_shell_script(tmp_path, monkeypatch):
    bindir, a, b = make_bin(tmp_path)
    monkeypatch.setenv("PATH", str(bindir))
    script = write(tmp_path / "tool", SCRIPT)

    assert calls_lines(script) == [
        "Functions:",
        "- helper",
        "Sources:",
        "- ./lib.sh",
        "Commands:",
        f"- fakeqa -> {a.resolve()} [python]",
        f"- fakeqb -> {b.resolve()} [shell]",
        "- fakeqc -> not found",
    ]


def test_calls_lines_with_nothing_found(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    assert calls_lines(script) == [
        "Functions:",
        "none",
        "Sources:",
        "none",
        "Commands:",
        "none",
    ]


def test_calls_lines_for_python_script(tmp_path):
    script = write(tmp_path / "tool", "#!/usr/bin/env python3\n")

    assert calls_lines(script) == [
        "Not a shell script (python): --calls reads shell scripts only"
    ]


def test_calls_lines_for_elf(tmp_path):
    binary = write(tmp_path / "tool", b"\x7fELF" + bytes(60))

    assert calls_lines(binary) == [
        "Not a shell script (elf): --calls reads shell scripts only"
    ]


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


def test_cli_calls_on_a_shell_script(tmp_path):
    bindir, a, b = make_bin(tmp_path)
    script = write(tmp_path / "tool", SCRIPT)

    result = run_xray(tmp_path, bindir, str(script), "--calls")

    assert result.returncode == 0
    assert "Calls of tool" in result.stdout
    assert f"- fakeqb -> {b.resolve()} [shell]" in result.stdout
    assert "- fakeqc -> not found" in result.stdout


def test_cli_calls_on_a_python_script(tmp_path):
    bindir, a, b = make_bin(tmp_path)
    script = write(tmp_path / "tool", "#!/usr/bin/env python3\n")

    result = run_xray(tmp_path, bindir, str(script), "--calls")

    assert result.returncode == 0
    assert "Not a shell script (python)" in result.stdout


def test_help_mentions_calls(tmp_path):
    result = run_xray(tmp_path, tmp_path, "--help")

    assert "--calls" in result.stdout
