import shutil
from pathlib import Path

from xray.command_analyzers import ELFAnalyzer, ShellAnalyzer
from xray.elfscan import scan_elf
from xray.model import Edge


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def of_kind(edges, kind, status):
    return [
        edge for edge in edges
        if edge.kind == kind and edge.status == status
    ]


def test_name_defaults_to_none():
    assert Edge("a", "b", "calls", "resolved").name is None


def test_name_is_stored():
    edge = Edge("a", "b", "runs", "resolved", name="grep")

    assert edge.name == "grep"


def test_name_is_not_part_of_equality():
    named = Edge("a", "b", "calls", "resolved", name="x")
    plain = Edge("a", "b", "calls", "resolved")

    assert named == plain


def test_shell_resolved_run_keeps_command_name(tmp_path):
    script = write(tmp_path / "tool.sh", "#!/bin/sh\nls\n")

    edges = ShellAnalyzer().edges(script)
    found = of_kind(edges, "runs", "resolved")

    assert [edge.name for edge in found] == ["ls"]
    assert Path(found[0].target).name != ""


def test_shell_unresolved_run_keeps_command_name(tmp_path):
    script = write(tmp_path / "tool.sh", "#!/bin/sh\nnosuchcmd_xyz\n")

    edges = ShellAnalyzer().edges(script)
    found = of_kind(edges, "runs", "unresolved")

    assert [edge.name for edge in found] == ["nosuchcmd_xyz"]


def test_shell_resolved_source_keeps_name_as_written(tmp_path):
    write(tmp_path / "lib.sh", "x=1\n")
    script = write(tmp_path / "tool.sh", "#!/bin/sh\nsource ./lib.sh\n")

    edges = ShellAnalyzer().edges(script)
    found = of_kind(edges, "sources", "resolved")

    assert [edge.name for edge in found] == ["./lib.sh"]


def test_shell_unresolved_source_keeps_name_as_written(tmp_path):
    script = write(tmp_path / "tool.sh", "#!/bin/sh\nsource ./gone.sh\n")

    edges = ShellAnalyzer().edges(script)
    found = of_kind(edges, "sources", "unresolved")

    assert [edge.name for edge in found] == ["./gone.sh"]


def test_elf_links_keep_library_names():
    binary = Path(shutil.which("ls")).resolve()
    needed = list(scan_elf(binary).needed)

    edges = ELFAnalyzer().edges(binary)

    assert needed
    assert [edge.name for edge in edges] == needed
