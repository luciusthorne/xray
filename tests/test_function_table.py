import lzma
import subprocess
from pathlib import Path

import xray.minidebug as minidebug_module
from xray.minidebug import parse_function_table, read_function_table

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


def elf(path):
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


def fake_run(section, text):
    def run(command, **kwargs):
        if command[0] == "objcopy" and section is not None:
            target = command[2].split("=", 1)[1]
            Path(target).write_bytes(section)

        return subprocess.CompletedProcess(command, 0, text, "")

    return run


def test_table_keeps_address_size_and_name_once():
    assert parse_function_table(TABLE) == (
        (0x3A00, 16, "dev_ino_hash"),
        (0x3A10, 41, "main"),
    )


def test_reads_the_table_from_the_compressed_section(tmp_path, monkeypatch):
    binary = elf(tmp_path / "prog")
    monkeypatch.setattr(
        minidebug_module.subprocess,
        "run",
        fake_run(lzma.compress(b"x"), TABLE),
    )

    assert read_function_table(binary) == (
        (0x3A00, 16, "dev_ino_hash"),
        (0x3A10, 41, "main"),
    )


def test_no_section_gives_an_empty_table(tmp_path, monkeypatch):
    binary = elf(tmp_path / "prog")
    monkeypatch.setattr(
        minidebug_module.subprocess, "run", fake_run(None, TABLE)
    )

    assert read_function_table(binary) == ()
