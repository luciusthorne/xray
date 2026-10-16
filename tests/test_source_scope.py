from xray.sourcelookup import find_definition

DEFINITION = "void\nmpz_add (int r)\n{\n  return;\n}\n"


def put(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_mini_implementation_is_not_the_installed_code(tmp_path):
    put(tmp_path, "mini-gmp/mini-gmp.c", DEFINITION)

    assert find_definition(tmp_path, "mpz_add") is None


def test_real_directory_wins_over_mini_implementation(tmp_path):
    put(tmp_path, "mini-gmp/mini-gmp.c", DEFINITION)
    put(tmp_path, "mpz/add.c", DEFINITION)

    found = find_definition(tmp_path, "mpz_add")

    assert found is not None
    assert found[0].parent.name == "mpz"
