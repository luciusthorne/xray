import os
import subprocess
import sys
from pathlib import Path

import xray.commandproject as cp
from xray.commandproject import project_lines, resolve_target_node
from xray.graph import DependencyGraph

REPO = Path(__file__).resolve().parent.parent


def sh(path, body="echo hi\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def setup(tmp_path):
    bindir = tmp_path / "fakebin"
    c = sh(bindir / "cpc")
    sh(bindir / "cpb", "cpc\n")
    tool = sh(tmp_path / "tool", "cpb\n")

    return bindir, tool, c


def run_xray(cwd, bindir, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd, env=env, capture_output=True, text=True, check=False,
    )


def test_name_resolves_through_path(tmp_path, monkeypatch):
    bindir, _tool, c = setup(tmp_path)
    monkeypatch.setenv("PATH", str(bindir))

    assert resolve_target_node("cpc") == str(c.resolve())


def test_path_with_slash_resolves(tmp_path):
    _, tool, _ = setup(tmp_path)

    assert resolve_target_node(str(tool)) == str(tool.resolve())


def test_library_name_resolves_through_find_library(tmp_path, monkeypatch):
    lib = tmp_path / "libq.so.1"
    lib.write_text("x", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(cp, "find_library", lambda name: lib.resolve())

    assert resolve_target_node("libq.so.1") == str(lib.resolve())


def test_unknown_target_is_none(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(cp, "find_library", lambda name: None)

    assert resolve_target_node("nosuchthing_xyz") is None
    assert resolve_target_node(str(tmp_path / "missing")) is None


def test_project_lines_report_the_command_graph():
    graph = DependencyGraph()
    graph.add_edge("/a/tool", "/usr/bin/b")
    graph.add_edge("/usr/bin/b", "/usr/lib64/libc.so.6")

    lines = project_lines(graph)

    assert lines[0] == "Command graph"
    assert "Files:  3" in lines
    assert "Edges:  2" in lines
    assert "Leaf files:  1" in lines
    assert "Cycles:  0" in lines
    assert any("library 1" in line for line in lines)
    assert "- /usr/lib64/libc.so.6: 1" in lines


def test_project_lines_count_cycles():
    graph = DependencyGraph()
    graph.add_edge("/a", "/b")
    graph.add_edge("/b", "/a")

    assert "Cycles:  1" in project_lines(graph)


def test_cli_path_between_commands(tmp_path):
    bindir, tool, c = setup(tmp_path)

    result = run_xray(tmp_path, bindir, str(tool), "--path", "cpc")

    assert result.returncode == 0
    assert str(tool.resolve()) in result.stdout
    assert str(c.resolve()) in result.stdout
    assert "No path found" not in result.stdout


def test_cli_path_to_an_unknown_target_exits_3(tmp_path):
    bindir, tool, _ = setup(tmp_path)

    result = run_xray(tmp_path, bindir, str(tool), "--path", "nosuchthing_xyz")

    assert result.returncode == 3
    assert "Target not found" in result.stderr


def test_cli_project_for_a_command(tmp_path):
    bindir, tool, _ = setup(tmp_path)

    result = run_xray(tmp_path, bindir, str(tool), "--project")

    assert result.returncode == 0
    assert "Command graph" in result.stdout
    assert "Files:  3" in result.stdout
