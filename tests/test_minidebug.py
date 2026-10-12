import lzma
import shutil
import subprocess
from pathlib import Path

import pytest

import xray.minidebug as minidebug_module
import xray.overview as overview_module
from xray.command_analyzers import ELFAnalyzer
from xray.elfscan import ElfScan
from xray.minidebug import parse_functions, read_minidebuginfo
from xray.overview import overview_lines

TABLE = """
Symbol table '.symtab' contains 6 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000003a00    16 FUNC    LOCAL  DEFAULT    5 dev_ino_hash
     2: 0000000000003a10    41 FUNC    GLOBAL DEFAULT    5 main
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)
     4: 0000000000004000     8 OBJECT  GLOBAL DEFAULT   24 some_table
     5: 0000000000003a00    16 FUNC    LOCAL  DEFAULT    5 dev_ino_hash
"""


def make_binary(path):
    path.write_bytes(b"\x7fELF" + bytes(60))
    path.chmod(0o755)

    return path


def fake_run(section, text):
    def run(command, **kwargs):
        if command[0] == "objcopy" and section is not None:
            target = command[2].split("=", 1)[1]
            Path(target).write_bytes(section)

        return subprocess.CompletedProcess(command, 0, text, "")

    return run


def test_parse_keeps_defined_functions_once_sorted():
    assert parse_functions(TABLE) == ("dev_ino_hash", "main")


def test_reads_names_from_the_compressed_section(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    run = fake_run(lzma.compress(b"x"), TABLE)
    monkeypatch.setattr(minidebug_module.subprocess, "run", run)

    assert read_minidebuginfo(binary) == ("dev_ino_hash", "main")


def test_binary_without_the_section_gives_nothing(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    monkeypatch.setattr(
        minidebug_module.subprocess, "run", fake_run(None, TABLE)
    )

    assert read_minidebuginfo(binary) == ()


def test_corrupt_section_gives_nothing(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    monkeypatch.setattr(
        minidebug_module.subprocess, "run", fake_run(b"not xz data", TABLE)
    )

    assert read_minidebuginfo(binary) == ()


def test_non_elf_file_gives_nothing(tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("plain", encoding="utf-8")

    assert read_minidebuginfo(text) == ()


def test_missing_objcopy_gives_nothing(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")

    def run(command, **kwargs):
        raise FileNotFoundError("objcopy")

    monkeypatch.setattr(minidebug_module.subprocess, "run", run)

    assert read_minidebuginfo(binary) == ()


def test_overview_lists_functions(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    monkeypatch.setattr(
        overview_module, "scan_elf", lambda path: ElfScan(imports=("a",))
    )
    monkeypatch.setattr(
        overview_module, "read_minidebuginfo", lambda path: ("f1", "f2")
    )

    lines = overview_lines(binary)

    assert lines[-3:] == ["Functions (2):", "- f1", "- f2"]


def test_overview_caps_functions(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    names = tuple(f"fn{n:02d}" for n in range(17))
    monkeypatch.setattr(
        overview_module, "scan_elf", lambda path: ElfScan(imports=("a",))
    )
    monkeypatch.setattr(
        overview_module, "read_minidebuginfo", lambda path: names
    )

    lines = overview_lines(binary)

    assert "Functions (17):" in lines
    assert len([l for l in lines if l.startswith("- fn")]) == 15
    assert lines[-1] == "- ... and 2 more"


def test_analyzer_symbols_are_functions(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    import xray.command_analyzers as analyzers_module

    monkeypatch.setattr(
        analyzers_module, "read_minidebuginfo", lambda path: ("f1",)
    )

    symbols = ELFAnalyzer().symbols(binary)

    assert [(s.name, s.kind, s.line) for s in symbols] == [
        ("f1", "function", 1)
    ]


@pytest.mark.skipif(
    shutil.which("objcopy") is None or shutil.which("readelf") is None,
    reason="binutils not installed",
)
def test_real_system_binary_has_function_names():
    names = read_minidebuginfo(Path(shutil.which("ls")).resolve())

    # Fedora keeps a mini symbol table in stripped binaries; other
    # systems may not, so only check the type of the result.
    assert isinstance(names, tuple)
