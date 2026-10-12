import os
import subprocess
import sys
from pathlib import Path

import xray.disasm as disasm_module
from xray.disasm import parse_calls, disasm_lines

REPO = Path(__file__).resolve().parent.parent

TEXT = """
/x/prog:     file format elf64-x86-64

Disassembly of section .init:

000000000000033c <.init>:
 33c:	endbr64
 350:	call   *%rax

Disassembly of section .plt:

0000000000000a10 <getenv@plt>:
 a10:	jmp    *0x1(%rip)

Disassembly of section .text:

0000000000001000 <helper>:
 1000:	call   a10 <getenv@plt>
 1004:	ret

0000000000001100 <main>:
 1100:	call   1000 <helper>
 1105:	call   1000 <helper>
 110a:	call   a10 <getenv@plt>
 1110:	call   110a <helper+0x8a>
 1116:	call   *%rdx
 111c:	call   *0x8(%rax)
"""


def test_parse_collects_internal_and_import_calls():
    result = parse_calls(TEXT)

    assert result.calls == {
        "helper": ("getenv@plt",),
        "main": ("getenv@plt", "helper"),
    }


def test_parse_counts_indirect_and_offset_calls():
    result = parse_calls(TEXT)

    assert result.indirect == 3
    assert result.offset == 1


def test_sections_without_functions_are_skipped():
    assert ".init" not in parse_calls(TEXT).calls
    assert "getenv@plt" not in parse_calls(TEXT).calls


def fake_run(text, returncode=0):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, returncode, text, "")

    return run


def elf(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


def test_lines_show_callers_and_totals(tmp_path, monkeypatch):
    monkeypatch.setattr(disasm_module.subprocess, "run", fake_run(TEXT))

    lines = disasm_lines(elf(tmp_path))

    assert "Functions that call others: 2" in lines
    assert "Indirect calls (not resolved): 3" in lines
    assert "Calls into the middle of a function (not resolved): 1" in lines
    assert "main" in lines
    assert "  -> helper" in lines
    assert "  -> getenv (import)" in lines


def test_callers_and_callees_are_capped(tmp_path, monkeypatch):
    body = "".join(
        f"{n:016x} <fn{n:02d}>:\n 1:\tcall   2 <t{n:02d}>\n" for n in range(45)
    )
    monkeypatch.setattr(disasm_module.subprocess, "run", fake_run(body))

    lines = disasm_lines(elf(tmp_path), max_callers=40)

    assert lines.count("... and 5 more functions") == 1


def test_missing_objdump_gives_a_message(tmp_path, monkeypatch):
    def run(command, **kwargs):
        raise FileNotFoundError("objdump")

    monkeypatch.setattr(disasm_module.subprocess, "run", run)

    assert disasm_lines(elf(tmp_path)) == [
        "objdump not found: install binutils to read calls"
    ]


def test_non_elf_gives_a_message(tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("plain", encoding="utf-8")

    assert disasm_lines(text) == ["Not an ELF binary: --disasm reads ELF only"]


def run_xray(cwd, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_help_mentions_disasm(tmp_path):
    assert "--disasm" in run_xray(tmp_path, "--help").stdout
