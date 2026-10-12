import os
import subprocess
import sys
from pathlib import Path

import xray.rizinview as rv
from xray.rizinview import function_lines

REPO = Path(__file__).resolve().parent.parent
TABLE = ((0x3A00, 16, "dev_ino_hash"), (0x3A10, 41, "dev_ino_compare"))


def elf(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


def patch(monkeypatch, stdout="LISTING\n", table=TABLE):
    calls = []

    def run(command, **kwargs):
        calls.append(command)

        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(rv.subprocess, "run", run)
    monkeypatch.setattr(rv, "read_function_table", lambda p: table)

    return calls


def test_known_name_runs_rizin_with_its_address(tmp_path, monkeypatch):
    calls = patch(monkeypatch)

    assert function_lines(elf(tmp_path), "dev_ino_hash") == ["LISTING"]
    assert calls[0][0] == "rizin"
    assert "aa; s 0x3a00; af; pdf" in calls[0]


def test_unknown_name_never_reaches_rizin(tmp_path, monkeypatch):
    calls = patch(monkeypatch)

    lines = function_lines(elf(tmp_path), "dev_ino_hsh; !rm -rf x")

    assert calls == []
    assert lines[0].startswith("Unknown function")


def test_close_matches_are_suggested(tmp_path, monkeypatch):
    patch(monkeypatch)

    lines = function_lines(elf(tmp_path), "dev_ino_hsh")

    assert "- dev_ino_hash" in lines


def test_output_is_capped(tmp_path, monkeypatch):
    patch(monkeypatch, stdout="\n".join(f"l{n}" for n in range(300)) + "\n")

    lines = function_lines(elf(tmp_path), "dev_ino_hash", max_lines=200)

    assert len(lines) == 201
    assert lines[-1] == "... and 100 more lines"


def test_missing_rizin_gives_a_message(tmp_path, monkeypatch):
    patch(monkeypatch)

    def run(command, **kwargs):
        raise FileNotFoundError("rizin")

    monkeypatch.setattr(rv.subprocess, "run", run)

    assert function_lines(elf(tmp_path), "dev_ino_hash") == [
        "rizin not found: install it with: sudo dnf install rizin"
    ]


def test_binary_without_function_names(tmp_path, monkeypatch):
    patch(monkeypatch, table=())

    assert function_lines(elf(tmp_path), "x") == [
        "No function names in this binary (it has no .gnu_debugdata)"
    ]


def test_non_elf_file(tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("plain", encoding="utf-8")

    assert function_lines(text, "x") == [
        "Not an ELF binary: --disasm-function reads ELF only"
    ]


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


def test_cli_requires_a_function_name():
    result = run_xray("ls", "--disasm-function")

    assert result.returncode == 2
    assert "Usage" in result.stderr


def test_help_mentions_it():
    assert "--disasm-function" in run_xray("--help").stdout
