import pytest

from xray import sourcelookup


def put(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def fake(monkeypatch, tmp_path):
    put(tmp_path, "gmp-h.in", "#define mpz_add __gmpz_add\n")
    put(tmp_path, "mpz/add.c", "void\nmpz_add (int r)\n{\n  return;\n}\n")
    calls = []

    monkeypatch.setattr(sourcelookup, "command_kind", lambda p: "elf")
    monkeypatch.setattr(
        sourcelookup, "read_function_table", lambda p: [(0, 0, "__gmpz_add")]
    )
    monkeypatch.setattr(sourcelookup, "_query", lambda p: ("gmp-1-1", "gmp-1-1.src"))

    def ensure(nvr, stem, say):
        calls.append(nvr)

        return tmp_path

    monkeypatch.setattr(sourcelookup, "ensure_source", ensure)

    return calls


def test_user_name_of_an_exported_alias_is_found(fake, tmp_path):
    lines = sourcelookup.source_lines(tmp_path / "lib.so", "mpz_add")

    assert "mpz/add.c:1" in lines[0]
    assert any("mpz_add is exported as __gmpz_add" in line for line in lines)
    assert "mpz_add (int r)" in lines


def test_typo_is_rejected_without_a_download(fake, tmp_path):
    lines = sourcelookup.source_lines(tmp_path / "lib.so", "mpz_adx")

    assert lines[0].startswith("Unknown function")
    assert fake == []
