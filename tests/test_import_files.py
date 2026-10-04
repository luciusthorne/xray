import os
import subprocess
import sys
from pathlib import Path

import pytest

from xray.entrypoints import import_files
from xray.launchgraph import build_launcher_graph

REPO = Path(__file__).resolve().parent.parent


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


@pytest.fixture
def installed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "pkgy" / "__init__.py")
    write(site / "pkgy" / "core.py", "def main():\n    pass\n")
    monkeypatch.syspath_prepend(str(site))

    return site


def run_xray(cwd, site, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO), str(site)])

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_relative_module_import(tmp_path):
    pkg = tmp_path / "pkg"
    write(pkg / "__init__.py")
    write(pkg / "b.py")
    a = write(pkg / "a.py", "from .b import thing\n")

    assert import_files(a) == [(pkg / "b.py").resolve()]


def test_relative_import_of_sibling_module(tmp_path):
    pkg = tmp_path / "pkg"
    write(pkg / "__init__.py")
    write(pkg / "sub.py")
    a = write(pkg / "a.py", "from . import sub\n")

    assert set(import_files(a)) == {
        (pkg / "__init__.py").resolve(),
        (pkg / "sub.py").resolve(),
    }


def test_relative_import_from_parent_package(tmp_path):
    pkg = tmp_path / "pkg"
    write(pkg / "__init__.py")
    write(pkg / "other.py")
    write(pkg / "inner" / "__init__.py")
    m = write(pkg / "inner" / "m.py", "from ..other import value\n")

    assert import_files(m) == [(pkg / "other.py").resolve()]


def test_relative_import_that_does_not_exist_is_skipped(tmp_path):
    pkg = tmp_path / "pkg"
    write(pkg / "__init__.py")
    a = write(pkg / "a.py", "from .nowhere import thing\n")

    assert import_files(a) == []


def test_absolute_from_import_of_a_submodule(tmp_path, installed):
    tool = write(tmp_path / "tool.py", "from pkgy import core\n")

    assert set(import_files(tool)) == {
        (installed / "pkgy" / "__init__.py").resolve(),
        (installed / "pkgy" / "core.py").resolve(),
    }


def test_from_import_of_a_name_adds_no_extra_file(tmp_path, installed):
    tool = write(tmp_path / "tool.py", "from pkgy.core import main\n")

    assert import_files(tool) == [
        (installed / "pkgy" / "core.py").resolve()
    ]


def test_stdlib_and_missing_modules_are_skipped(tmp_path):
    tool = write(
        tmp_path / "tool.py",
        "import os\nimport not_installed_xyz\nfrom json import loads\n",
    )

    assert import_files(tool) == []


def test_star_import(tmp_path, installed):
    tool = write(tmp_path / "tool.py", "from pkgy import *\n")

    assert import_files(tool) == [
        (installed / "pkgy" / "__init__.py").resolve()
    ]


def test_broken_file_gives_nothing(tmp_path):
    tool = write(tmp_path / "tool.py", "def (:\n")

    assert import_files(tool) == []


def test_launcher_graph_follows_relative_imports(tmp_path, installed):
    write(installed / "pkgy" / "a.py", "from .b import value\n")
    write(installed / "pkgy" / "b.py")
    command = write(
        tmp_path / "bin" / "toolr",
        "#!/usr/bin/env python3\nimport pkgy.a\n",
    )

    a = str((installed / "pkgy" / "a.py").resolve())
    b = str((installed / "pkgy" / "b.py").resolve())

    shallow = build_launcher_graph(command, max_depth=1)
    deep = build_launcher_graph(command, max_depth=2)

    assert b not in shallow.nodes
    assert (a, b) in set(deep.edges)


def test_cli_launch_depth_goes_deeper(tmp_path, installed):
    write(installed / "pkgy" / "a.py", "from .b import value\n")
    b = write(installed / "pkgy" / "b.py")
    command = write(
        tmp_path / "bin" / "toolr",
        "#!/usr/bin/env python3\nimport pkgy.a\n",
    )

    shallow = run_xray(tmp_path, installed, str(command), "--launch")
    deep = run_xray(
        tmp_path, installed, str(command), "--launch-depth", "2"
    )

    assert str(b.resolve()) not in shallow.stdout
    assert deep.returncode == 0
    assert str(b.resolve()) in deep.stdout


def test_cli_launch_depth_rejects_bad_values(tmp_path, installed):
    command = write(
        tmp_path / "bin" / "toolr",
        "#!/usr/bin/env python3\nimport pkgy.core\n",
    )

    for value in ("0", "abc"):
        result = run_xray(
            tmp_path, installed, str(command), "--launch-depth", value
        )

        assert result.returncode != 0

    result = run_xray(tmp_path, installed, str(command), "--launch-depth")

    assert result.returncode != 0
