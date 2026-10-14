from xray.sourcelookup import file_lines, index_functions

C = "static int\nalpha (void)\n{\n  return 1;\n}\n\nbeta (void);\n"


def test_index_finds_bodies_and_skips_tests_and_prototypes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text(C, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.c").write_text("zeta (void)\n{\n}\n", encoding="utf-8")

    found = index_functions(tmp_path, ["alpha", "beta", "zeta"])

    assert found == {"alpha": ("src/a.c", 2)}


def test_file_lines_are_numbered_and_capped(tmp_path):
    (tmp_path / "a.c").write_text("\n".join(f"l{n}" for n in range(10)), encoding="utf-8")

    lines = file_lines(tmp_path, "a.c", max_lines=3)

    assert lines[0] == "    1  l0"
    assert lines[-1] == "... and 7 more lines"


def test_file_lines_refuse_paths_outside_the_root(tmp_path):
    (tmp_path / "root").mkdir()
    (tmp_path / "secret.c").write_text("x", encoding="utf-8")

    assert file_lines(tmp_path / "root", "../secret.c") == ["Not a source file"]
