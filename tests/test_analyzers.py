import pytest

from xray.analyzers import Analyzer, Registry, registry


class ShellOnly(Analyzer):
    name = "shell"
    kinds = ("shell",)


class AlsoShell(Analyzer):
    name = "shell2"
    kinds = ("shell",)


class PythonOnly(Analyzer):
    name = "python"
    kinds = ("python",)


def write(path, text):
    path.write_text(text, encoding="utf-8")

    return path


def test_registry_finds_analyzer_by_kind(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")
    shell = ShellOnly()
    items = Registry()
    items.register(PythonOnly())
    items.register(shell)

    assert items.analyzer_for(script) is shell


def test_registry_returns_none_when_nothing_handles_the_file(tmp_path):
    other = write(tmp_path / "notes.txt", "plain text\n")
    items = Registry()
    items.register(ShellOnly())

    assert items.analyzer_for(other) is None


def test_first_registered_match_wins(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/bash\necho hi\n")
    first = ShellOnly()
    items = Registry()
    items.register(first)
    items.register(AlsoShell())

    assert items.analyzer_for(script) is first
    assert items.names() == ["shell", "shell2"]


def test_duplicate_name_is_rejected():
    items = Registry()
    items.register(ShellOnly())

    with pytest.raises(ValueError):
        items.register(ShellOnly())


def test_empty_name_is_rejected():
    with pytest.raises(ValueError):
        Registry().register(Analyzer())


def test_base_analyzer_defaults_are_empty(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\n")
    analyzer = ShellOnly()

    assert analyzer.can_handle(script)
    assert analyzer.edges(script) == []
    assert analyzer.symbols(script) == []


def test_default_registry_exists():
    assert isinstance(registry, Registry)
