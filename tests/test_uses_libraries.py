import xray.uses as uses_module
from xray.elfscan import ElfScan
from xray.uses import attribute_imports, uses_lines


def fake_scan(table):
    def scan(path):
        return table.get(str(path), ElfScan())

    return scan


def elf(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


def test_names_are_attributed_to_the_library_that_exports_them():
    exports = {"libfoo.so.1": {"foo_open", "foo_close"}, "libbar.so.2": {"bar_x"}}

    result = attribute_imports(
        ("foo_open", "bar_x", "foo_close", "nobody_has_it"), exports
    )

    assert result == {
        "libfoo.so.1": ("foo_close", "foo_open"),
        "libbar.so.2": ("bar_x",),
    }


def test_first_library_wins_for_a_shared_name():
    exports = {"liba.so": {"dup"}, "libb.so": {"dup"}}

    assert attribute_imports(("dup",), exports) == {"liba.so": ("dup",)}


def test_libc_names_stay_in_purpose_groups(tmp_path, monkeypatch):
    binary = elf(tmp_path)
    lib = tmp_path / "libfoo.so.1"
    lib.write_text("x", encoding="utf-8")
    scans = {
        str(binary): ElfScan(
            needed=("libfoo.so.1",), imports=("open", "foo_open", "zzz")
        ),
        str(lib.resolve()): ElfScan(exports=("foo_open", "open")),
    }
    monkeypatch.setattr(uses_module, "scan_elf", fake_scan(scans))
    monkeypatch.setattr(uses_module, "ldconfig_cache", lambda: {"libfoo.so.1": str(lib)})
    monkeypatch.setattr(uses_module, "package_of", lambda p: "foopkg-1-1.noarch")

    lines = uses_lines(binary)

    assert "files (1):" in lines
    assert "- open" in lines
    assert "From libfoo.so.1 (foopkg-1-1.noarch) (1):" in lines
    assert "- foo_open" in lines
    assert "other (1):" in lines
    assert "- zzz" in lines


def test_missing_library_leaves_names_as_other(tmp_path, monkeypatch):
    binary = elf(tmp_path)
    scans = {str(binary): ElfScan(needed=("libgone.so.1",), imports=("gone_fn",))}
    monkeypatch.setattr(uses_module, "scan_elf", fake_scan(scans))
    monkeypatch.setattr(uses_module, "ldconfig_cache", dict)

    lines = uses_lines(binary)

    assert "other (1):" in lines
    assert "- gone_fn" in lines
