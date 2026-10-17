from xray import discover


def test_resolve_target_finds_library_name(tmp_path, monkeypatch):
    library = tmp_path / "libexample.so.1"
    library.write_text("", encoding="utf-8")

    monkeypatch.setattr(discover.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        discover, "find_library", lambda name: library.resolve()
    )

    assert discover.resolve_target("libexample.so.1") == library.resolve()


def test_resolve_target_returns_none_for_unknown_target(monkeypatch):
    monkeypatch.setattr(discover.shutil, "which", lambda name: None)
    monkeypatch.setattr(discover, "find_library", lambda name: None)

    assert discover.resolve_target("no-such-library-xyz") is None


def test_resolve_target_prefers_existing_path(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.write_text("", encoding="utf-8")

    def unexpected_lookup(name):
        raise AssertionError("Library lookup should not run for an existing path")

    monkeypatch.setattr(discover, "find_library", unexpected_lookup)

    assert discover.resolve_target(str(target)) == target.resolve()


def test_resolve_target_prefers_executable_over_library(
    tmp_path, monkeypatch
):
    executable = tmp_path / "example"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(
        discover.shutil, "which", lambda name: str(executable)
    )

    def unexpected_lookup(name):
        raise AssertionError("Library lookup should not run")

    monkeypatch.setattr(discover, "find_library", unexpected_lookup)

    assert discover.resolve_target("example") == executable.resolve()
