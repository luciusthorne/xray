import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import xray.command_analyzers as analyzers_module
import xray.graphjson as graphjson_module
from xray import __version__
from xray.elfscan import ElfScan
from xray.graphjson import graph_data

REPO = Path(__file__).resolve().parent.parent


def write(path, text, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")

    path.chmod(mode)

    return path


def sh(path, body="echo hi\n"):
    return write(path, "#!/bin/sh\n" + body)


@pytest.fixture(autouse=True)
def no_rpm(monkeypatch):
    monkeypatch.setattr(graphjson_module, "package_of", lambda path: None)


def by_name(edges):
    return sorted(edges, key=lambda edge: edge["name"])


def test_shell_graph(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "gjb", "gjc\n")
    c = sh(bindir / "gjc")
    tool = sh(tmp_path / "tool", "gjb\n")
    monkeypatch.setenv("PATH", str(bindir))

    data = graph_data(tool)

    assert data["root"] == str(tool.resolve())
    assert {node["id"]: node["kind"] for node in data["nodes"]} == {
        str(tool.resolve()): "shell",
        str(b.resolve()): "shell",
        str(c.resolve()): "shell",
    }
    assert by_name(data["edges"]) == [
        {
            "source": str(tool.resolve()),
            "target": str(b.resolve()),
            "kind": "runs",
            "status": "resolved",
            "name": "gjb",
        },
        {
            "source": str(b.resolve()),
            "target": str(c.resolve()),
            "kind": "runs",
            "status": "resolved",
            "name": "gjc",
        },
    ]
    assert data["metadata"]["truncated"] is False


def test_unresolved_edges_keep_their_name(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    tool = sh(tmp_path / "tool", "gjmissing\n")

    data = graph_data(tool)

    assert len(data["nodes"]) == 1
    assert data["edges"] == [
        {
            "source": str(tool.resolve()),
            "target": None,
            "kind": "runs",
            "status": "unresolved",
            "name": "gjmissing",
        }
    ]


def test_cycles_terminate(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    a = sh(bindir / "gja", "gjb\n")
    sh(bindir / "gjb", "gja\n")
    monkeypatch.setenv("PATH", str(bindir))

    data = graph_data(a)

    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 2
    assert data["metadata"]["truncated"] is False


def test_depth_limit_is_reported(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    sh(bindir / "gjb", "gjc\n")
    sh(bindir / "gjc")
    tool = sh(tmp_path / "tool", "gjb\n")
    monkeypatch.setenv("PATH", str(bindir))

    data = graph_data(tool, max_depth=1)

    assert len(data["nodes"]) == 2
    assert data["metadata"]["truncated"] is True
    assert data["metadata"]["max_depth"] == 1


def test_no_truncation_when_the_graph_ends_at_the_limit(
    tmp_path, monkeypatch
):
    bindir = tmp_path / "fakebin"
    sh(bindir / "gjb")
    tool = sh(tmp_path / "tool", "gjb\n")
    monkeypatch.setenv("PATH", str(bindir))

    data = graph_data(tool, max_depth=1)

    assert len(data["nodes"]) == 2
    assert data["metadata"]["truncated"] is False


def test_file_limit_is_reported(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"

    for name in ("gjx", "gjy", "gjz"):
        sh(bindir / name)

    tool = sh(tmp_path / "tool", "gjx\ngjy\ngjz\n")
    monkeypatch.setenv("PATH", str(bindir))

    data = graph_data(tool, max_files=2)

    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1
    assert data["metadata"]["truncated"] is True


def test_python_launcher_graph(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "pkgg" / "__init__.py", "", 0o644)
    a = write(site / "pkgg" / "a.py", "x = 1\n", 0o644)
    monkeypatch.syspath_prepend(str(site))
    tool = write(tmp_path / "tool", "#!/usr/bin/env python3\nimport pkgg.a\n")

    data = graph_data(tool)

    nodes = {node["id"]: node for node in data["nodes"]}

    assert nodes[str(tool.resolve())]["kind"] == "python"
    assert nodes[str(a.resolve())]["kind"] == "python"
    assert nodes[str(a.resolve())]["symbol_count"] == 1
    assert data["edges"] == [
        {
            "source": str(tool.resolve()),
            "target": str(a.resolve()),
            "kind": "imports",
            "status": "resolved",
            "name": "a.py",
        }
    ]


def test_elf_libraries_are_library_nodes(tmp_path, monkeypatch):
    binary = write(tmp_path / "prog", b"\x7fELF" + bytes(60))
    lib = write(tmp_path / "libfoo.so.1", "x", 0o644)

    monkeypatch.setattr(
        analyzers_module,
        "scan_elf",
        lambda path: ElfScan(needed=("libfoo.so.1", "libgone.so.1")),
    )
    monkeypatch.setattr(
        analyzers_module, "ldconfig_cache", lambda: {"libfoo.so.1": str(lib)}
    )

    data = graph_data(binary)

    assert {node["id"]: node["kind"] for node in data["nodes"]} == {
        str(binary.resolve()): "elf",
        str(lib.resolve()): "library",
    }
    assert by_name(data["edges"]) == [
        {
            "source": str(binary.resolve()),
            "target": str(lib.resolve()),
            "kind": "links",
            "status": "resolved",
            "name": "libfoo.so.1",
        },
        {
            "source": str(binary.resolve()),
            "target": None,
            "kind": "links",
            "status": "unresolved",
            "name": "libgone.so.1",
        },
    ]


def test_nodes_carry_their_package(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "gjb")
    tool = sh(tmp_path / "tool", "gjb\n")
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr(
        graphjson_module,
        "package_of",
        lambda path: "pkg-1-1.noarch" if str(path).endswith("gjb") else None,
    )

    nodes = {node["id"]: node for node in graph_data(tool)["nodes"]}

    assert nodes[str(b.resolve())]["package"] == "pkg-1-1.noarch"
    assert nodes[str(tool.resolve())]["package"] is None


def test_output_is_deterministic_and_serializable(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    sh(bindir / "gjb")
    sh(bindir / "gjc")
    tool = sh(tmp_path / "tool", "gjc\ngjb\n")
    monkeypatch.setenv("PATH", str(bindir))

    first = graph_data(tool)
    second = graph_data(tool)

    assert first == second
    assert json.loads(json.dumps(first)) == first


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


def test_cli_graph_json_is_pure_json(tmp_path):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "gjb")
    tool = sh(tmp_path / "tool", "gjb\n")

    result = run_xray(tmp_path, bindir, str(tool), "--graph-json")

    assert result.returncode == 0

    data = json.loads(result.stdout)

    assert data["metadata"]["xray_version"] == __version__
    assert any(node["id"] == str(b.resolve()) for node in data["nodes"])


def test_cli_graph_json_errors_go_to_stderr(tmp_path):
    result = run_xray(tmp_path, tmp_path, "missing_cmd_xyz", "--graph-json")

    assert result.returncode == 3
    assert result.stdout == ""
    assert "Command not found" in result.stderr


def test_help_mentions_graph_json(tmp_path):
    result = run_xray(tmp_path, tmp_path, "--help")

    assert "--graph-json" in result.stdout
