from xray.sourcelookup import find_definition


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


GMP_PATTERN = """\
#ifdef OPERATION_add
#define FUNCTION mpz_add
#define VARIATION
#endif
#ifdef OPERATION_sub
#define FUNCTION mpz_sub
#define VARIATION -
#endif

void
FUNCTION (int operation)
{
  return;
}
"""


def test_macro_generated_add_definition_is_found(tmp_path):
    write(tmp_path, "mpz/aors.h", GMP_PATTERN)

    result = find_definition(tmp_path, "mpz_add")

    assert result is not None
    path, _line, shown, others = result
    assert path.name == "aors.h"
    assert "FUNCTION (int operation)" in shown
    assert shown[-1] == "}"
    assert others == 0


def test_macro_generated_sub_definition_is_found(tmp_path):
    write(tmp_path, "mpz/aors.h", GMP_PATTERN)

    result = find_definition(tmp_path, "mpz_sub")

    assert result is not None
    path, _line, shown, others = result
    assert path.name == "aors.h"
    assert "FUNCTION (int operation)" in shown
    assert shown[-1] == "}"
    assert others == 0


def test_macro_lookup_does_not_match_an_unrelated_function(tmp_path):
    write(
        tmp_path,
        "mpz/aors.h",
        "#define FUNCTION mpz_add\n"
        "void\nFUNCTION (int operation)\n{\n  return;\n}\n",
    )

    assert find_definition(tmp_path, "mpz_mul") is None


def test_literal_definition_still_works(tmp_path):
    write(
        tmp_path,
        "ordinary.c",
        "void\nordinary_function (void)\n{\n  return;\n}\n",
    )

    result = find_definition(tmp_path, "ordinary_function")

    assert result is not None
    assert "ordinary_function (void)" in result[2]


def test_macro_lookup_identifies_the_requested_definition(tmp_path):
    write(tmp_path, "mpz/aors.h", GMP_PATTERN)

    add = find_definition(tmp_path, "mpz_add")
    sub = find_definition(tmp_path, "mpz_sub")

    assert add is not None and sub is not None

    # Both names share a template, but the matching macro definitions differ.
    assert "#define FUNCTION mpz_add" in add[2]
    assert "#define FUNCTION mpz_sub" not in add[2]
    assert "#define FUNCTION mpz_sub" in sub[2]
    assert "#define FUNCTION mpz_add" not in sub[2]
