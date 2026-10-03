import dataclasses

import pytest

from xray.symbols import SYMBOL_KINDS, Symbol


def test_symbol_fields():
    symbol = Symbol(
        name="hello",
        kind="function",
        file="example.py",
        line=3,
    )

    assert symbol.name == "hello"
    assert symbol.kind == "function"
    assert symbol.file == "example.py"
    assert symbol.line == 3


def test_symbol_defaults():
    symbol = Symbol("hello", "function", "example.py", 1)

    assert symbol.parent is None
    assert symbol.metadata == {}


def test_known_kinds():
    assert SYMBOL_KINDS == (
        "function",
        "class",
        "method",
        "variable",
    )


def test_qualified_name_top_level():
    symbol = Symbol("hello", "function", "example.py", 1)

    assert symbol.qualified_name == "hello"


def test_qualified_name_method():
    symbol = Symbol(
        "save",
        "method",
        "example.py",
        7,
        parent="User",
    )

    assert symbol.qualified_name == "User.save"


def test_unknown_kind_is_rejected():
    with pytest.raises(ValueError, match="Unknown symbol kind"):
        Symbol("x", "module", "example.py", 1)


def test_symbol_is_immutable():
    symbol = Symbol("hello", "function", "example.py", 1)

    with pytest.raises(dataclasses.FrozenInstanceError):
        symbol.name = "other"


def test_symbol_equality_ignores_metadata():
    first = Symbol(
        "hello", "function", "example.py", 1,
        metadata={"async": True},
    )
    second = Symbol("hello", "function", "example.py", 1)

    assert first == second
    assert hash(first) == hash(second)


def test_symbol_is_hashable():
    symbol = Symbol("hello", "function", "example.py", 1)

    assert symbol in {symbol}


def test_metadata_is_not_shared_between_symbols():
    first = Symbol("a", "variable", "example.py", 1)
    second = Symbol("b", "variable", "example.py", 2)

    first.metadata["note"] = "x"

    assert second.metadata == {}
