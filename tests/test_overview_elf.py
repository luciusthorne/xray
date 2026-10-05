import xray.overview as overview_module
from xray.elfscan import ElfScan
from xray.overview import overview_lines


def make_binary(path):
    path.write_bytes(b"\x7fELF" + bytes(60))
    path.chmod(0o755)

    return path


def test_libraries_show_their_package(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    lib = tmp_path / "libfoo.so.1"
    lib.write_text("x", encoding="utf-8")

    monkeypatch.setattr(
        overview_module,
        "scan_elf",
        lambda path: ElfScan(
            needed=("libfoo.so.1",),
            interpreter="/lib64/ld.so",
            imports=("a", "b"),
        ),
    )
    monkeypatch.setattr(
        overview_module, "ldconfig_cache", lambda: {"libfoo.so.1": str(lib)}
    )
    monkeypatch.setattr(
        overview_module, "package_of", lambda path: "foopkg-1-1.noarch"
    )

    assert overview_lines(binary) == [
        "Interpreter:",
        "- /lib64/ld.so",
        "Libraries:",
        f"- libfoo.so.1 -> {lib.resolve()} (foopkg-1-1.noarch)",
        "Imports: 2 (use --calls to list them)",
    ]


def test_missing_and_unowned_libraries(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    lib = tmp_path / "libfoo.so.1"
    lib.write_text("x", encoding="utf-8")

    monkeypatch.setattr(
        overview_module,
        "scan_elf",
        lambda path: ElfScan(needed=("libfoo.so.1", "libovgone.so.1")),
    )
    monkeypatch.setattr(
        overview_module, "ldconfig_cache", lambda: {"libfoo.so.1": str(lib)}
    )
    monkeypatch.setattr(overview_module, "package_of", lambda path: None)

    lines = overview_lines(binary)

    assert f"- libfoo.so.1 -> {lib.resolve()}" in lines
    assert "- libovgone.so.1 -> not found" in lines
    assert "Interpreter:" in lines
    assert "none" in lines


def test_library_list_is_capped(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")
    names = tuple(f"libovcap{n:02d}.so" for n in range(17))

    monkeypatch.setattr(
        overview_module, "scan_elf", lambda path: ElfScan(needed=names)
    )
    monkeypatch.setattr(overview_module, "ldconfig_cache", lambda: {})
    monkeypatch.setattr(overview_module, "package_of", lambda path: None)

    lines = overview_lines(binary)
    shown = [line for line in lines if line.startswith("- libovcap")]

    assert len(shown) == 15
    assert "- ... and 2 more" in lines


def test_elf_without_readable_information(tmp_path, monkeypatch):
    binary = make_binary(tmp_path / "prog")

    monkeypatch.setattr(
        overview_module, "scan_elf", lambda path: ElfScan()
    )

    assert overview_lines(binary) == [
        "No ELF information found (is readelf installed?)"
    ]
