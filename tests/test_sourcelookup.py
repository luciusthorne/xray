from xray.sourcelookup import base_name, find_definition

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

    file, line, shown, others = find_definition(tmp_path, "dev_ino_hash")

    assert (line, shown[0], shown[-1]) == (4, "static size_t", "}")
    assert find_definition(tmp_path, "dev_ino_compare") is None
    assert find_definition(tmp_path, "nothing") is None
