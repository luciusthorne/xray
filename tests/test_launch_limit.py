import os
import subprocess
import sys
from pathlib import Path

import pytest

from xray.launchgraph import (
    build_launcher_graph,
    build_launcher_graph_info,
    launch_lines,
)

REPO = Path(__file__).resolve().parent.parent


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


@pytest.fixture
def installed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "libw" / "__init__.py")

    for name in ("a", "b", "c"):
        write(site / "libw" / f"{name}.py")

    monkeypatch.syspath_prepend(str(site))

    return site


@pytest.fixture
def command(tmp_path):
    return write(
        tmp_path / "bin" / "toolw",
        "#!/usr/bin/env python3\n"
        "import libw.a\nimport libw.b\nimport libw.c\n",
    )


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


def test_info_reports_truncation(command, installed):
    graph, truncated = build_launcher_graph_info(command, max_files=2)

    assert truncated is True
    assert len(graph.nodes) == 2


def test_info_reports_no_truncation_when_everything_fits(
    command, installed
):
    graph, truncated = build_launcher_graph_info(command, max_files=10)

    assert truncated is False
    assert len(graph.nodes) == 4


def test_exactly_at_the_limit_is_not_truncated(command, installed):
    graph, truncated = build_launcher_graph_info(command, max_files=4)

    assert truncated is False
    assert len(graph.nodes) == 4


def test_build_launcher_graph_still_returns_a_graph(command, installed):
    graph = build_launcher_graph(command, max_files=2)

    assert len(graph.nodes) == 2


def test_default_limit_is_200(command, installed):
    import inspect

    default = inspect.signature(build_launcher_graph).parameters[
        "max_files"
    ].default

    assert default == 200


def test_launch_lines_notice_when_truncated(command, installed):
    lines = launch_lines(command, max_files=2)

    assert lines[-1] == "Truncated: file limit (2) reached"


def test_launch_lines_no_notice_when_complete(command, installed):
    lines = launch_lines(command, max_files=10)

    assert not any(line.startswith("Truncated") for line in lines)


def test_cli_launch_limit(tmp_path, installed, command):
    result = run_xray(
        tmp_path, installed, str(command), "--launch-limit", "2"
    )

    assert result.returncode == 0
    assert "Truncated: file limit (2) reached" in result.stdout


def test_cli_launch_limit_large_enough(tmp_path, installed, command):
    result = run_xray(
        tmp_path, installed, str(command), "--launch-limit", "50"
    )

    assert result.returncode == 0
    assert "Truncated" not in result.stdout


def test_cli_launch_limit_rejects_bad_values(
    tmp_path, installed, command
):
    for value in ("0", "abc"):
        result = run_xray(
            tmp_path, installed, str(command), "--launch-limit", value
        )

        assert result.returncode != 0

    result = run_xray(tmp_path, installed, str(command), "--launch-limit")

    assert result.returncode != 0


def test_help_mentions_launch_limit(tmp_path, installed):
    result = run_xray(tmp_path, installed, "--help")

    assert "--launch-limit" in result.stdout
