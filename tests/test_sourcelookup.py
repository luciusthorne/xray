from pathlib import Path

from xray import sourcelookup
from xray.sourcelookup import base_name, binary_stems, find_definition

C = """static bool
dev_ino_compare (void const *x, void const *y);

static size_t
dev_ino_hash (void const *x, size_t table_size)
{
  struct dev_ino const *p = x;
  return 0;
}

other (void)
{
}
"""


def test_variants_are_stripped():
    assert base_name("quotearg.constprop.0") == "quotearg"
    assert base_name("sort_files.cold") == "sort_files"
    assert base_name("f.isra.0.cold") == "f"
    assert base_name("plain") == "plain"


def test_definition_includes_return_type_and_skips_prototypes(tmp_path):
    (tmp_path / "ls.c").write_text(C, encoding="utf-8")

    _file, line, shown, _others = find_definition(tmp_path, "dev_ino_hash")

    assert (line, shown[0], shown[-1]) == (4, "static size_t", "}")
    assert find_definition(tmp_path, "dev_ino_compare") is None
    assert find_definition(tmp_path, "nothing") is None


def test_definition_supports_same_line_signatures_and_nested_bodies(tmp_path):
    (tmp_path / "tool.c").write_text(
        "int tool(void) { if (1) { return 7; } return 0; }\n"
    )

    file, line, shown, others = find_definition(tmp_path, "tool")

    assert file.name == "tool.c"
    assert line == 1
    assert shown == ["int tool(void) { if (1) { return 7; } return 0; }"]
    assert others == 0


def test_call_inside_function_is_not_mistaken_for_definition(tmp_path):
    (tmp_path / "tool.c").write_text(
        "int main(void) {\n  return missing_function();\n}\n"
    )

    assert find_definition(tmp_path, "missing_function") is None


def test_source_lines_uses_configured_local_tree_without_package_fetch(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir()
    (source / "tool.c").write_text("int\nrun_tool(void)\n{\n  return 7;\n}\n")
    binary = tmp_path / "tool"
    binary.write_bytes(b"fixture")
    monkeypatch.setenv("XRAY_SOURCE_PATH", str(source))
    monkeypatch.setattr(sourcelookup, "command_kind", lambda _path: "elf")
    monkeypatch.setattr(sourcelookup, "read_function_table", lambda _path: [(0, 1, "run_tool")])
    monkeypatch.setattr(sourcelookup, "_query", lambda _path: (_ for _ in ()).throw(AssertionError("must not fetch package metadata")))

    assert sourcelookup.source_lines(binary, "run_tool") == [
        "tool.c:1", "(local source tree)", "int", "run_tool(void)", "{", "  return 7;", "}"
    ]


def test_cached_source_listing_includes_configured_local_tree(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir()
    (source / "tool.c").write_text("int\nrun_tool(void)\n{\n  return 7;\n}\n")
    binary = tmp_path / "tool"
    binary.write_bytes(b"fixture")
    monkeypatch.setenv("XRAY_SOURCE_PATH", str(source))
    monkeypatch.setattr(sourcelookup, "command_kind", lambda _path: "elf")
    monkeypatch.setattr(sourcelookup, "read_function_table", lambda _path: [(0, 1, "run_tool")])
    monkeypatch.setattr(sourcelookup, "_query", lambda _path: (_ for _ in ()).throw(AssertionError("must not query package metadata")))

    assert sourcelookup.cached_source_files(binary) == {"tool.c": ["run_tool"]}


def test_source_lines_uses_debuginfod_before_package_lookup(tmp_path, monkeypatch):
    binary = tmp_path / "tool"
    binary.write_bytes(b"fixture")
    cached = tmp_path / "remote-source.c"
    cached.write_text("int\nrun_tool(void)\n{\n  return 9;\n}\n")
    monkeypatch.delenv("XRAY_SOURCE_PATH", raising=False)
    monkeypatch.setattr(sourcelookup, "command_kind", lambda _path: "elf")
    monkeypatch.setattr(sourcelookup, "read_function_table", lambda _path: [])
    monkeypatch.setattr(
        "xray.debuginfod.configured", lambda: True
    )
    monkeypatch.setattr(
        "xray.debuginfod.function_source",
        lambda _path, _name: (Path("/usr/src/tool.c"), cached, 2),
    )
    monkeypatch.setattr(
        sourcelookup,
        "_query",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not query package metadata")),
    )

    assert sourcelookup.source_lines(binary, "run_tool") == [
        "/usr/src/tool.c:1",
        "(source from debuginfod)",
        "int",
        "run_tool(void)",
        "{",
        "  return 9;",
        "}",
    ]


def test_source_cache_listing_and_selective_remove(tmp_path, monkeypatch):
    root = tmp_path / "src"
    first = root / "pkg-1"
    second = root / "pkg-2"
    first.mkdir(parents=True)
    second.mkdir()
    (first / ".done").write_text("ok\n")
    (first / "source.c").write_text("1234")
    (second / "partial").write_text("ignored")
    monkeypatch.setattr(sourcelookup, "cache_root", lambda: root)

    assert sourcelookup.source_cache_entries() == [("pkg-1", 7)]
    assert sourcelookup.remove_source_cache("pkg-1") == 1
    assert second.exists()


def test_source_cache_remove_rejects_symlinks(tmp_path, monkeypatch):
    root = tmp_path / "src"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "pkg").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(sourcelookup, "cache_root", lambda: root)

    try:
        sourcelookup.remove_source_cache("pkg")
    except ValueError as error:
        assert "symlink" in str(error)
    else:
        raise AssertionError("symlink cache entry should be rejected")
    assert outside.exists()


def test_source_cache_size_limit_prunes_oldest_but_keeps_active(tmp_path, monkeypatch):
    root = tmp_path / "src"
    old = root / "old"
    active = root / "active"
    old.mkdir(parents=True)
    active.mkdir()
    (old / ".done").write_text("ok\n")
    (active / ".done").write_text("ok\n")
    (old / "source.c").write_text("x" * 100)
    (active / "source.c").write_text("y" * 100)
    monkeypatch.setattr(sourcelookup, "cache_root", lambda: root)
    monkeypatch.setenv("XRAY_SOURCE_CACHE_MAX_MIB", "0")

    sourcelookup._prune_source_cache(active)

    assert not old.exists()
    assert active.exists()


def test_definition_prefers_the_binarys_own_file(tmp_path):
    (tmp_path / "gl" / "lib").mkdir(parents=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "gl" / "lib" / "randint.c").write_text("int\nmain (void)\n{\n  return 1;\n}\n")
    (tmp_path / "src" / "cat.c").write_text("int\nmain (void)\n{\n  return 2;\n}\n")
    (tmp_path / "src" / "ls.c").write_text("int\nmain (void)\n{\n  return 3;\n}\n")
    (tmp_path / "tests" / "ls.c").write_text("int\nmain (void)\n{\n  return 4;\n}\n")

    file, _line, shown, others = find_definition(tmp_path, "main", prefer=binary_stems("/usr/bin/ls"))

    assert file == tmp_path / "src" / "ls.c"
    assert "  return 3;" in shown
    assert others == 3


def test_binary_stems_include_library_name_without_prefix():
    assert binary_stems("/usr/lib64/libgmp.so.10.5.0") == {"libgmp", "gmp"}
    assert binary_stems("/usr/bin/ls") == {"ls"}
