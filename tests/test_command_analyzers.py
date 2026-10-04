import shutil
from pathlib import Path

import pytest

from xray.analyzers import registry
from xray.command_analyzers import ELFAnalyzer, ShellAnalyzer
from xray.model import Edge


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def test_shell_unfound_command_is_unresolved(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\nnosuchcmd_xyz\n")

    assert ShellAnalyzer().edges(script) == [
        Edge(str(script.resolve()), "nosuchcmd_xyz", "runs", "unresolved")
    ]


def test_shell_found_command_is_resolved(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\nls\n")
    target = Path(shutil.which("ls")).resolve()

    assert ShellAnalyzer().edges(script) == [
        Edge(str(script.resolve()), str(target), "runs", "resolved")
    ]


def test_shell_relative_source_resolves_next_to_script(tmp_path):
    lib = write(tmp_path / "lib.sh", "#!/bin/sh\n")
    script = write(tmp_path / "tool", "#!/bin/sh\nsource ./lib.sh\n")

    assert ShellAnalyzer().edges(script) == [
        Edge(str(script.resolve()), str(lib.resolve()), "sources", "resolved")
    ]


def test_shell_missing_source_is_unresolved(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\nsource ./gone.sh\n")

    assert ShellAnalyzer().edges(script) == [
        Edge(str(script.resolve()), "./gone.sh", "sources", "unresolved")
    ]


def test_shell_script_with_no_commands_has_no_edges(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    assert ShellAnalyzer().edges(script) == []


@pytest.mark.skipif(
    shutil.which("readelf") is None, reason="readelf not installed"
)
def test_elf_links_edges():
    binary = Path(shutil.which("sh")).resolve()
    edges = ELFAnalyzer().edges(binary)

    assert edges
    assert all(edge.kind == "links" for edge in edges)
    assert all(edge.source == str(binary) for edge in edges)
    assert any(edge.status == "resolved" for edge in edges)


def test_both_registered_in_default_registry():
    assert "shell" in registry.names()
    assert "elf" in registry.names()
