import os
import subprocess
import sys
from pathlib import Path

import xray.disasm as disasm_module
from xray.disasm import assembly_lines, disasm_lines, parse_calls

REPO = Path(__file__).resolve().parent.parent

# Addresses and sizes come from the real symbol table of /usr/bin/ls
# (.gnu_debugdata). The error_body function is invented to hold the
# call sites that were seen at 129c to 161f.
TABLE = (
    (0x10C0, 31, "sort_files.cold"),
    (0x10DF, 43, "flush_stdout"),
    (0x110A, 124, "print_errno_message"),
    (0x1186, 124, "error_tail"),
    (0x1202, 0x500, "error_body"),
    (0x181C0, 18, "atexit"),
)

SLICE = """
0000000000001202 <error@@Base>:
    10da:\tcall   c70 <__assert_fail@plt>
    11bc:\tcall   110a <__sprintf_chk@plt+0x8a>
    129c:\tcall   10df <__sprintf_chk@plt+0x5f>
    12ea:\tcall   1186 <__sprintf_chk@plt+0x106>
    143f:\tcall   10df <__sprintf_chk@plt+0x5f>
    14bf:\tcall   1186 <__sprintf_chk@plt+0x106>
    161f:\tcall   181c0 <error_at_line@@Base+0x16e68>
    1210:\tcall   1130 <print_errno_message+0x26>
    1220:\tcall   fffff0 <x@@Base+0x1>
    1500:\tcall   *%rax
"""


def test_named_disassembly_rejects_nearest_symbol_offsets(tmp_path, monkeypatch):
    binary = tmp_path / "tool"
    binary.write_bytes(b"\x7fELF" + bytes(60))
    output = """tool: file format elf64-x86-64
00001000 <error@@Base-0x20>:
    1000: ret
00002000 <error@@Base>:
    2000: ret
00003000 <error_at_line@@Base>:
    3000: ret
"""
    monkeypatch.setattr(
        disasm_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, ""),
    )

    assert assembly_lines(binary, "error")[-2:] == [
        "00002000 <error@@Base>:", "    2000: ret"
    ]


def test_calls_are_resolved_by_address():
    result = parse_calls(SLICE, TABLE)

    assert result.calls == {
        "sort_files.cold": ("__assert_fail@plt",),
        "error_tail": ("print_errno_message",),
        "error_body": ("atexit", "error_tail", "flush_stdout"),
    }
    assert result.indirect == 1
    assert result.offset == 1
    assert result.unresolved == 1
    assert result.unattributed == 0


def test_without_symbol_names_calls_are_not_attributed():
    result = parse_calls(SLICE, ())

    assert result.calls == {}
    assert result.indirect == 1
    assert result.unattributed == 9


def test_indirect_calls_are_counted_not_resolved():
    text = " 1100:\tcall   *%rdx\n 1104:\tcall   *0x8(%rax)\n"

    assert parse_calls(text, TABLE).indirect == 2


def fake_run(text, returncode=0):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, returncode, text, "")

    return run


def elf(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


def test_lines_show_callers_and_totals(tmp_path, monkeypatch):
    text = (
        " 1004:\tcall   a10 <getenv@plt>\n"
        " 1104:\tcall   1000 <helper>\n"
        " 1108:\tcall   *%rdx\n"
    )
    table = ((0x1000, 16, "helper"), (0x1100, 16, "main"))
    monkeypatch.setattr(disasm_module.subprocess, "run", fake_run(text))
    monkeypatch.setattr(disasm_module, "read_function_table", lambda p: table)

    lines = disasm_lines(elf(tmp_path))

    assert "Functions that call others: 2" in lines
    assert "Indirect calls (not resolved): 1" in lines
    assert "main" in lines
    assert "  -> helper" in lines
    assert "  -> getenv (import)" in lines


def test_callers_are_capped(tmp_path, monkeypatch):
    table = tuple((0x1000 + n * 0x10, 16, f"fn{n:02d}") for n in range(45))
    text = "".join(
        f" {0x1000 + n * 0x10 + 4:x}:\tcall   2 <imp@plt>\n" for n in range(45)
    )
    monkeypatch.setattr(disasm_module.subprocess, "run", fake_run(text))
    monkeypatch.setattr(disasm_module, "read_function_table", lambda p: table)

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


def test_help_mentions_disasm(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    result = subprocess.run(
        [sys.executable, "-m", "xray.cli", "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert "--disasm" in result.stdout
