"""Brace counting ignores strings, character literals and comments (grep.c's main was missed)."""

from xray.sourcelookup import find_definition, find_definition_file

TRICKY = r'''
static char const open_brace = '{';
static char const *fmt = "%{color}s }}} \" {";
/* a comment with { braces
   over two lines { */
// and a line comment {

static void
helper (void)
{
  puts ("}");
}

int
main (int argc, char **argv)
{
  return helper (), 0;
}
'''


def test_braces_in_literals_and_comments_do_not_hide_definitions(tmp_path):
    source = tmp_path / "grep.c"
    source.write_text(TRICKY)

    _file, _line, shown, _others = find_definition_file(source, "main")
    assert shown[:2] == ["int", "main (int argc, char **argv)"]
    assert shown[-1] == "}"

    found = find_definition(tmp_path, "helper")
    assert found is not None
    assert found[2][-1] == "}"


def test_line_hint_picks_the_nearest_definition(tmp_path):
    source = tmp_path / "two.c"
    source.write_text("#if A\nint\nf (void)\n{\n  return 1;\n}\n#else\nint\nf (void)\n{\n  return 2;\n}\n#endif\n")

    assert find_definition_file(source, "f")[1] == 2
    assert find_definition_file(source, "f", near=9)[1] == 8
