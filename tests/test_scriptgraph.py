"""Shell script call graphs: functions calling functions, commands per function, line numbers."""

import subprocess
import sys
from pathlib import Path

from xray.scriptgraph import TOP, callgraph_lines, shell_graph

REPO = Path(__file__).resolve().parents[1]

SCRIPT = """#!/bin/sh
. ./lib.sh

help() {
    cat <<EOF
usage: { not code } "quotes ' here
EOF
}

fetch() {
    curl -s "$1" | grep x
}

work() {
    data=$(fetch "$1")
    sudo install -m 644 "$data" /tmp/x
    help
}

unused() {
    echo never
}

work "$@"
"""


def _script(tmp_path):
    path = tmp_path / "tool"
    path.write_text(SCRIPT)
    path.chmod(0o755)
    return path


def test_functions_calls_commands_and_spans(tmp_path):
    graph = shell_graph(_script(tmp_path))

    assert graph.functions["help"] == (4, 8)  # the heredoc's braces and quotes do not stretch it
    assert graph.functions["work"] == (14, 18)
    assert graph.calls["work"] == {"fetch": [15], "help": [17]}  # $(...) counts, inside work
    assert set(graph.commands["work"]) == {"sudo", "install"}  # sudo and the command it runs
    assert set(graph.commands["fetch"]) == {"curl", "grep"}
    assert graph.calls[TOP] == {"work": [24]}
    assert graph.sources[TOP] == {"./lib.sh": [2]}


def test_text_views(tmp_path):
    graph = shell_graph(_script(tmp_path))

    whole = "\n".join(callgraph_lines(graph, "tool"))
    assert "→ fetch  (defined at line 10; called at line 15)" in whole
    assert "Not called by any function or the top level: unused" in whole

    one = "\n".join(callgraph_lines(graph, "tool", focus="fetch"))
    assert "← work  (line 15)" in one and "curl: line 11" in one
    assert "No function named" in callgraph_lines(graph, "tool", focus="nope")[0]


def test_cli(tmp_path):
    path = _script(tmp_path)
    result = subprocess.run([sys.executable, "-m", "xray.cli", str(path), "--callgraph", "work"],
                            cwd=REPO, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "→ fetch" in result.stdout and "← (top level)" in result.stdout
