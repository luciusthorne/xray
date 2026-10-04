import pytest

from xray.launchgraph import build_launcher_graph


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


@pytest.fixture
def installed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "libq" / "__init__.py")
    monkeypatch.syspath_prepend(str(site))

    return site


def launcher(tmp_path, body):
    return write(
        tmp_path / "bin" / "toolq",
        "#!/usr/bin/env python3\n" + body,
    )


def test_command_without_imports_is_a_single_node(tmp_path):
    command = launcher(tmp_path, "print('hi')\n")

    graph = build_launcher_graph(command)

    assert set(graph.nodes) == {str(command.resolve())}
    assert set(graph.edges) == set()


def test_follows_launcher_into_installed_package(tmp_path, installed):
    write(installed / "libq" / "core.py", "def main():\n    pass\n")
    command = launcher(tmp_path, "from libq.core import main\nmain()\n")

    graph = build_launcher_graph(command)

    source = str(command.resolve())
    target = str((installed / "libq" / "core.py").resolve())

    assert set(graph.nodes) == {source, target}
    assert set(graph.edges) == {(source, target)}


def test_stdlib_imports_are_skipped(tmp_path):
    command = launcher(tmp_path, "import os\nimport json\n")

    graph = build_launcher_graph(command)

    assert len(graph.nodes) == 1
    assert set(graph.edges) == set()


def test_missing_modules_are_skipped(tmp_path):
    command = launcher(tmp_path, "import not_installed_xyz\n")

    graph = build_launcher_graph(command)

    assert len(graph.nodes) == 1
    assert set(graph.edges) == set()


def test_depth_limits_how_far_it_follows(tmp_path, installed):
    write(installed / "libq" / "core.py", "import libq.util\n")
    write(installed / "libq" / "util.py", "")
    command = launcher(tmp_path, "import libq.core\n")

    core = str((installed / "libq" / "core.py").resolve())
    util = str((installed / "libq" / "util.py").resolve())

    shallow = build_launcher_graph(command, max_depth=1)

    assert util not in shallow.nodes

    deep = build_launcher_graph(command, max_depth=2)

    assert util in deep.nodes
    assert (core, util) in set(deep.edges)


def test_max_files_caps_the_graph(tmp_path, installed):
    for name in ("a", "b", "c"):
        write(installed / "libq" / f"{name}.py")

    command = launcher(
        tmp_path, "import libq.a\nimport libq.b\nimport libq.c\n"
    )

    graph = build_launcher_graph(command, max_files=2)

    assert len(graph.nodes) == 2


def test_cycles_terminate(tmp_path, installed):
    write(installed / "libq" / "a.py", "import libq.b\n")
    write(installed / "libq" / "b.py", "import libq.a\n")
    command = launcher(tmp_path, "import libq.a\n")

    graph = build_launcher_graph(command, max_depth=10)

    a = str((installed / "libq" / "a.py").resolve())
    b = str((installed / "libq" / "b.py").resolve())

    assert len(graph.nodes) == 3
    assert (a, b) in set(graph.edges)
    assert (b, a) in set(graph.edges)


def test_shell_command_is_a_single_node(tmp_path):
    command = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    graph = build_launcher_graph(command)

    assert set(graph.nodes) == {str(command.resolve())}
    assert set(graph.edges) == set()
