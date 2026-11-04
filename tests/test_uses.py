import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import xray.overview as overview_module
import xray.uses as uses_module
from xray.elfscan import ElfScan
from xray.overview import overview_lines
from xray.uses import GROUPS, group_imports, uses_lines, uses_summary

REPO = Path(__file__).resolve().parent.parent


def test_a_name_belongs_to_one_group_only():
    counts = Counter(n for names in GROUPS.values() for n in names)

    assert [n for n, c in counts.items() if c > 1] == []


def test_names_are_grouped_by_purpose():
    found = group_imports(
        ("open", "malloc", "__fprintf_chk", "selinux_foo", "zzz_unknown")
    )

    assert found == {
        "files": ("open",),
        "memory": ("malloc",),
        "stdio": ("__fprintf_chk",),
        "security": ("selinux_foo",),
        "other": ("zzz_unknown",),
    }


def test_variants_are_normalized():
    found = group_imports(
        ("__memcpy_chk", "fputs_unlocked", "__isoc23_strtoumax", "stat64")
    )

    assert set(found) == {"memory", "stdio", "strings", "files"}


def test_summary_is_none_when_nothing_is_grouped():
    assert uses_summary(("zzz1", "zzz2")) is None
    assert uses_summary(()) is None


def test_summary_lists_groups_by_size_with_other_last():
    line = uses_summary(("open", "close", "malloc", "zzz"))

    assert line == "Uses: files (2), memory (1), other (1)"


def elf(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


def test_overview_shows_a_uses_line(tmp_path, monkeypatch):
    monkeypatch.setattr(
        overview_module,
        "scan_elf",
        lambda p: ElfScan(imports=("open", "malloc")),
    )
    monkeypatch.setattr(overview_module, "read_function_table", lambda p: ())

    lines = overview_lines(elf(tmp_path))

    assert "Uses: files (1), memory (1)" in lines


def test_overview_has_no_uses_line_for_unknown_names(tmp_path, monkeypatch):
    monkeypatch.setattr(
        overview_module, "scan_elf", lambda p: ElfScan(imports=("a", "b"))
    )
    monkeypatch.setattr(overview_module, "read_function_table", lambda p: ())

    assert not any(
        line.startswith("Uses:") for line in overview_lines(elf(tmp_path))
    )


def test_uses_lines_list_names_per_group(tmp_path, monkeypatch):
    monkeypatch.setattr(
        uses_module, "scan_elf", lambda p: ElfScan(imports=("open", "zzz"))
    )

    lines = uses_lines(elf(tmp_path))

    assert "files (1):" in lines
    assert "- open" in lines
    assert "other (1):" in lines
    assert lines[-1].startswith("A name here means")


def test_uses_lines_for_a_non_elf_file(tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("plain", encoding="utf-8")

    assert uses_lines(text) == ["No ELF information found (is readelf installed?)"]


def test_help_mentions_uses(tmp_path):
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

    assert "--uses" in result.stdout
