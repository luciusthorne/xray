from xray.analysis_views import (
    call_coupling_lines,
    call_graph_lines,
    coupling_lines,
    unused_symbols_lines,
)
from xray.callgraph import CallGraph
from xray.cli import build_graph


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def make_call_graph():
    graph = CallGraph()
    graph.add_call("a.py:f", "b.py:g")
    graph.add_call("a.py:f", "a.py:h")
    graph.add_unresolved("a.py:f", "dynamic", "unresolved")

    return graph


def test_call_graph_lines_lists_callees_and_unresolved():
    lines = call_graph_lines(make_call_graph(), "a.py")

    assert lines[:5] == [
        "a.py:f",
        "  -> a.py:h",
        "  -> b.py:g",
        "  ? dynamic (unresolved)",
        "a.py:h",
    ]
    assert lines[-1] == "Calls that cannot be resolved statically are marked with ?."


def test_call_graph_lines_none_for_unknown_file():
    assert call_graph_lines(make_call_graph(), "zzz.py") == ["none"]


def test_call_graph_lines_list_only_the_requested_file():
    lines = call_graph_lines(make_call_graph(), "a.py")

    assert "b.py:g" not in lines


def test_unused_symbols_lines_reports_orphan(tmp_path):
    write(
        tmp_path / "utils.py",
        "def used():\n    return 1\n\n\ndef orphan():\n    return 2\n",
    )
    main = write(tmp_path / "main.py", "from utils import used\n\nused()\n")

    lines = unused_symbols_lines(main)

    assert "- function: orphan (utils.py, line 5)" in lines
    assert not any(line.startswith("- function: used ") for line in lines)
    assert lines[-1].startswith("Static analysis result")


def test_unused_symbols_lines_none_without_definitions(tmp_path):
    source = write(tmp_path / "a.py", "import os\n")

    assert unused_symbols_lines(source) == ["none"]


def test_coupling_lines_show_fan_in_and_fan_out(tmp_path):
    root = tmp_path.resolve()
    a = write(root / "a.py", "import b\n")
    write(root / "b.py", "x = 1\n")

    lines = coupling_lines(build_graph(root, a), "a.py")

    assert lines[0].startswith("Modules:")
    assert any(line.startswith("Density:") for line in lines)
    assert "This file: a.py: fan-in 0, fan-out 1" in lines
    assert "- b.py: fan-in 1, fan-out 0" in lines


def test_call_coupling_lines_count_calls_between_modules(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "from utils import calculate\n"
        "\n"
        "\n"
        "def main():\n"
        "    calculate()\n",
    )

    lines = call_coupling_lines(main)

    assert "- main.py: calls out 1, calls in 0" in lines
    assert "- utils.py: calls out 0, calls in 1" in lines
