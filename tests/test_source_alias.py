from xray.sourcelookup import elf_alias


def put(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_header_define_maps_user_name_to_exported_name(tmp_path):
    put(tmp_path, "gmp-h.in", "#define mpz_add __gmpz_add\n")

    assert elf_alias(tmp_path, "mpz_add", {"__gmpz_add", "other"}) == "__gmpz_add"


def test_define_to_a_name_the_elf_does_not_export_is_ignored(tmp_path):
    put(tmp_path, "gmp-h.in", "#define mpz_add __gmpz_add\n")

    assert elf_alias(tmp_path, "mpz_add", {"something_else"}) is None


def test_name_without_a_define_has_no_alias(tmp_path):
    put(tmp_path, "gmp-h.in", "#define mpz_sub __gmpz_sub\n")

    assert elf_alias(tmp_path, "mpz_add", {"__gmpz_add"}) is None
