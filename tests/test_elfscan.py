import shutil
import sys

import pytest

from xray.elfscan import (
    ElfScan,
    parse_dynamic,
    parse_interp,
    parse_symbols,
    scan_elf,
)

DYNAMIC = """
Dynamic section at offset 0x16b70 contains 29 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libz.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x33c
"""

SYMBOLS = """
Symbol table '.dynsym' contains 6 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __strcat_chk@GLIBC_2.3.4 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.2.5 (3)
     3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     4: 0000000000001130    42 FUNC    GLOBAL DEFAULT   14 do_work
     5: 0000000000004010     8 OBJECT  GLOBAL DEFAULT   25 counter@@VER_1
"""


def test_parse_dynamic_lists_needed_libraries():
    assert parse_dynamic(DYNAMIC) == ("libc.so.6", "libz.so.1")


def test_parse_dynamic_without_dynamic_section():
    text = "There is no dynamic section in this file.\n"

    assert parse_dynamic(text) == ()


def test_parse_symbols_imports_and_exports():
    imports, exports = parse_symbols(SYMBOLS)

    assert imports == ("__gmon_start__", "__strcat_chk", "getenv")
    assert exports == ("counter", "do_work")


def test_parse_symbols_strips_versions_and_skips_unnamed():
    imports, exports = parse_symbols(SYMBOLS)

    assert not any("@" in name for name in imports + exports)
    assert "" not in imports


def test_parse_symbols_are_unique():
    text = (
        "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND open@GLIBC_2.2.5 (2)\n"
        "     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND open@GLIBC_2.9 (3)\n"
    )

    assert parse_symbols(text) == (("open",), ())


def test_parse_symbols_of_garbage_is_empty():
    assert parse_symbols("nothing useful here\n") == ((), ())


def test_parse_interp():
    text = (
        "String dump of section '.interp':\n"
        "  [     0]  /lib64/ld-linux-x86-64.so.2\n"
    )

    assert parse_interp(text) == "/lib64/ld-linux-x86-64.so.2"


def test_parse_interp_when_missing():
    assert parse_interp("readelf: Warning: Section '.interp' was not dumped\n") is None


def test_scan_of_non_elf_is_empty(tmp_path):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

    assert scan_elf(path) == ElfScan()


def test_scan_of_missing_file_is_empty(tmp_path):
    assert scan_elf(tmp_path / "nope") == ElfScan()


def test_scan_without_readelf_is_empty(tmp_path, monkeypatch):
    path = tmp_path / "tool"
    path.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    assert scan_elf(path) == ElfScan()


@pytest.mark.skipif(
    shutil.which("readelf") is None, reason="readelf not installed"
)
def test_scan_of_a_real_binary():
    scan = scan_elf(sys.executable)

    if scan == ElfScan():
        pytest.skip("interpreter is not a readable ELF binary")

    assert scan.needed
    assert scan.imports
