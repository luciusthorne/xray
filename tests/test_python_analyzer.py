import pytest

from xray.analyzers import registry
from xray.errors import AnalysisError
from xray.model import Edge
from xray.python_analyzer import PythonAnalyzer


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def edges_of(path, root, kind):
    return [
        edge
        for edge in PythonAnalyzer().edges(path, root)
        if edge.kind == kind
    ]


def test_symbols_wraps_extraction(tmp_path):
    source = write(tmp_path / "a.py", "def f():\n    pass\n")

    symbols = PythonAnalyzer().symbols(source)

    assert [(s.name, s.kind) for s in symbols] == [("f", "function")]


def test_import_edges_resolve_local_files(tmp_path):
    other = write(tmp_path / "b.py")
    source = write(tmp_path / "a.py", "import b\n")

    assert edges_of(source, tmp_path, "imports") == [
        Edge(
            str(source.resolve()),
            str(other.resolve()),
            "imports",
            "resolved",
        )
    ]


def test_stdlib_imports_are_external(tmp_path):
    source = write(tmp_path / "a.py", "import os\n")

    assert edges_of(source, tmp_path, "imports") == [
        Edge(str(source.resolve()), "os", "imports", "external")
    ]


def test_missing_local_import_is_unresolved(tmp_path):
    source = write(tmp_path / "a.py", "from . import missing\n")

    assert edges_of(source, tmp_path, "imports") == [
        Edge(str(source.resolve()), None, "imports", "unresolved")
    ]


def test_call_edges(tmp_path):
    source = write(
        tmp_path / "a.py",
        "def g():\n    pass\n\n\ndef f():\n    g()\n",
    )

    assert edges_of(source, tmp_path, "calls") == [
        Edge("a.py:f", "a.py:g", "calls", "resolved")
    ]


def test_inherits_edges(tmp_path):
    source = write(
        tmp_path / "a.py",
        "class A:\n    pass\n\n\nclass B(A):\n    pass\n",
    )

    assert edges_of(source, tmp_path, "inherits") == [
        Edge("a.py:B", "a.py:A", "inherits", "resolved")
    ]


def test_reference_edges(tmp_path):
    write(tmp_path / "b.py", "def helper():\n    pass\n")
    source = write(
        tmp_path / "a.py",
        "from b import helper\n\n\ndef f():\n    helper()\n",
    )

    assert edges_of(source, tmp_path, "references") == [
        Edge("a.py", "b.py:helper", "references", "resolved")
    ]


def test_invalid_python_raises_analysis_error(tmp_path):
    source = write(tmp_path / "a.py", "def broken(:\n")

    with pytest.raises(AnalysisError):
        PythonAnalyzer().edges(source, tmp_path)


def test_registered_in_default_registry(tmp_path):
    source = write(tmp_path / "a.py", "x = 1\n")

    assert "python" in registry.names()
    assert isinstance(registry.analyzer_for(source), PythonAnalyzer)
