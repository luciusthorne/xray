import os
import subprocess
import sys
from pathlib import Path

from xray.project_graph import build_project_graph

REPO = Path(__file__).resolve().parent.parent


def test_project_graph_uses_registered_python_and_shell_analyzers(tmp_path):
    (tmp_path / "main.py").write_text("import helper\n", encoding="utf-8")
    (tmp_path / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "tool.sh").write_text(
        "#!/bin/sh\n. ./lib.sh\n", encoding="utf-8"
    )
    (tmp_path / "lib.sh").write_text("helper() { :; }\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not source\n", encoding="utf-8")

    graph = build_project_graph(tmp_path, tmp_path)

    assert graph.nodes == {"main.py", "helper.py", "tool.sh", "lib.sh"}
    assert ("main.py", "helper.py") in graph.edges
    assert ("tool.sh", "lib.sh") in graph.edges


def test_project_graph_skips_hidden_and_generated_folders(tmp_path):
    (tmp_path / "main.py").write_text("import helper\n", encoding="utf-8")
    hidden = tmp_path / ".venv"
    hidden.mkdir()
    (hidden / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    generated = tmp_path / "__pycache__"
    generated.mkdir()
    (generated / "module.py").write_text("VALUE = 2\n", encoding="utf-8")

    graph = build_project_graph(tmp_path, tmp_path)

    assert graph.nodes == {"main.py"}
    assert graph.edges == []


def test_project_report_counts_multiple_supported_languages(tmp_path):
    (tmp_path / "main.py").write_text(
        "import sys\nfrom . import absent_module\nimport helper\n",
        encoding="utf-8",
    )
    (tmp_path / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "tool.sh").write_text(
        "#!/bin/sh\n. ./lib.sh\n", encoding="utf-8"
    )
    (tmp_path / "lib.sh").write_text("helper() { :; }\n", encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    result = subprocess.run(
        [sys.executable, "-m", "xray", str(tmp_path / "main.py"), "--project"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Source files:      4" in result.stdout
    assert "Languages:         Python 2, Shell 2" in result.stdout
    assert "Dependency edges:  2" in result.stdout
    assert "External dependencies: 1" in result.stdout
    assert "Unresolved dependencies: 1" in result.stdout


def test_project_graph_retains_external_and_unresolved_imports(tmp_path):
    source = tmp_path / "main.py"
    source.write_text(
        "import sys\nfrom . import absent_module\n", encoding="utf-8"
    )

    graph = build_project_graph(tmp_path, tmp_path)

    assert graph.external_edges == [("main.py", "imports", "sys")]
    assert graph.unresolved_edges == [
        ("main.py", "imports", ".absent_module")
    ]
