import os
import subprocess
import sys
from pathlib import Path

from xray.graph import DependencyGraph
from xray.graphjson import command_graph

REPO = Path(__file__).resolve().parent.parent


def sh(path, body="echo hi\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def setup(tmp_path):
    bindir = tmp_path / "fakebin"
    c = sh(bindir / "cgc")
    b = sh(bindir / "cgb", "cgc\n")
    tool = sh(tmp_path / "tool", "cgb\n")

    return bindir, tool, b, c


def run_xray(cwd, bindir, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_command_graph_is_a_dependency_graph(tmp_path, monkeypatch):
    bindir, tool, b, c = setup(tmp_path)
    monkeypatch.setenv("PATH", str(bindir))

    graph = command_graph(tool)

    assert isinstance(graph, DependencyGraph)
    assert graph.dependencies_of(str(tool.resolve())) == [str(b.resolve())]
    assert graph.dependencies_of(str(b.resolve())) == [str(c.resolve())]


def test_unresolved_commands_are_not_nodes(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    tool = sh(tmp_path / "tool", "cgmissing\n")

    graph = command_graph(tool)

    assert graph.nodes == {str(tool.resolve())}
    assert graph.edges == []


def test_cli_tree_for_a_command(tmp_path):
    bindir, tool, b, c = setup(tmp_path)

    result = run_xray(tmp_path, bindir, str(tool), "--tree")

    assert result.returncode == 0
    assert str(b.resolve()) in result.stdout
    assert str(c.resolve()) in result.stdout


def test_cli_deps_for_a_command(tmp_path):
    bindir, tool, b, c = setup(tmp_path)

    result = run_xray(tmp_path, bindir, str(tool), "--deps")

    assert result.returncode == 0
    assert str(b.resolve()) in result.stdout


def test_cli_impact_for_a_command(tmp_path):
    bindir, tool, b, c = setup(tmp_path)

    result = run_xray(tmp_path, bindir, str(c), "--impact")

    assert result.returncode == 0
    assert result.stdout.strip() != ""


def test_cli_cycles_for_a_command(tmp_path):
    bindir = tmp_path / "fakebin"
    a = sh(bindir / "cga", "cgb2\n")
    sh(bindir / "cgb2", "cga\n")

    result = run_xray(tmp_path, bindir, str(a), "--cycles")

    assert result.returncode == 0
    assert str(a.resolve()) in result.stdout
