import pytest

from xray.errors import AnalysisError, FileError
from xray.symbols import (
    Symbol,
    extract_symbols,
    extract_symbols_from_source,
)


def test_top_level_function():
    symbols = extract_symbols_from_source(
        "def hello():\n    pass\n",
        "example.py",
    )

    assert symbols == [
        Symbol("hello", "function", "example.py", 1),
    ]


def test_async_function_is_marked():
    symbols = extract_symbols_from_source(
        "async def fetch():\n    pass\n",
        "example.py",
    )

    assert len(symbols) == 1
    assert symbols[0].kind == "function"
    assert symbols[0].metadata == {"async": True}


def test_class_with_methods():
    source = (
        "class User:\n"
        "    def save(self):\n"
        "        pass\n"
        "\n"
        "    def delete(self):\n"
        "        pass\n"
    )

    symbols = extract_symbols_from_source(source, "example.py")

    assert [
        (s.qualified_name, s.kind, s.line) for s in symbols
    ] == [
        ("User", "class", 1),
        ("User.save", "method", 2),
        ("User.delete", "method", 5),
    ]


def test_async_method_is_marked():
    source = (
        "class Client:\n"
        "    async def fetch(self):\n"
        "        pass\n"
    )

    symbols = extract_symbols_from_source(source, "example.py")

    assert symbols[1].kind == "method"
    assert symbols[1].parent == "Client"
    assert symbols[1].metadata == {"async": True}


def test_nested_class():
    source = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def run(self):\n"
        "            pass\n"
    )

    symbols = extract_symbols_from_source(source, "example.py")

    assert [
        (s.qualified_name, s.kind, s.line) for s in symbols
    ] == [
        ("Outer", "class", 1),
        ("Outer.Inner", "class", 2),
        ("Outer.Inner.run", "method", 3),
    ]


def test_local_definitions_are_ignored():
    source = (
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
        "\n"
        "    class Local:\n"
        "        pass\n"
        "\n"
        "    value = 1\n"
    )

    symbols = extract_symbols_from_source(source, "example.py")

    assert [(s.name, s.kind) for s in symbols] == [
        ("outer", "function"),
    ]


def test_module_variables():
    symbols = extract_symbols_from_source(
        "x = 1\ny = z = 2\n",
        "example.py",
    )

    assert [(s.name, s.kind, s.line) for s in symbols] == [
        ("x", "variable", 1),
        ("y", "variable", 2),
        ("z", "variable", 2),
    ]


def test_annotated_variable():
    symbols = extract_symbols_from_source(
        "count: int = 0\n",
        "example.py",
    )

    assert [(s.name, s.kind, s.line) for s in symbols] == [
        ("count", "variable", 1),
    ]


def test_results_follow_source_order():
    source = (
        "VERSION = 1\n"
        "\n"
        "def run():\n"
        "    pass\n"
        "\n"
        "class App:\n"
        "    pass\n"
    )

    symbols = extract_symbols_from_source(source, "example.py")

    assert [(s.name, s.line) for s in symbols] == [
        ("VERSION", 1),
        ("run", 3),
        ("App", 6),
    ]


def test_empty_source():
    assert extract_symbols_from_source("", "example.py") == []


def test_imports_and_calls_are_not_symbols():
    source = "import os\nprint('hello')\n"

    assert extract_symbols_from_source(source, "example.py") == []


def test_extract_symbols_from_file(tmp_path):
    target = tmp_path / "example.py"
    target.write_text(
        "def hello():\n    pass\n",
        encoding="utf-8",
    )

    symbols = extract_symbols(target)

    assert symbols == [
        Symbol("hello", "function", str(target), 1),
    ]


def test_extract_symbols_missing_file(tmp_path):
    with pytest.raises(FileError):
        extract_symbols(tmp_path / "missing.py")


def test_extract_symbols_invalid_syntax(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")

    with pytest.raises(AnalysisError):
        extract_symbols(broken)
