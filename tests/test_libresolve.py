from xray.libresolve import find_library, ldconfig_cache, parse_ldconfig

SAMPLE = """\
3 libs found in cache `/etc/ld.so.cache'
\tlibz.so.1 (libc6,x86-64) => /lib64/libz.so.1
\tlibc.so.6 (libc6,x86-64) => /lib64/libc.so.6
\tlibc.so.6 (libc6) => /lib/libc.so.6
"""


def touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")

    return path


def test_parse_ldconfig_first_entry_wins():
    assert parse_ldconfig(SAMPLE) == {
        "libz.so.1": "/lib64/libz.so.1",
        "libc.so.6": "/lib64/libc.so.6",
    }


def test_parse_ldconfig_ignores_other_lines():
    assert parse_ldconfig("nothing here\n\n") == {}


def test_find_library_uses_the_cache(tmp_path):
    lib = touch(tmp_path / "somewhere" / "libq.so.1")

    assert find_library("libq.so.1", {"libq.so.1": str(lib)}, dirs=()) == (
        lib.resolve()
    )


def test_find_library_falls_back_to_directories(tmp_path):
    lib = touch(tmp_path / "libs" / "libx.so.1")

    assert find_library("libx.so.1", {}, dirs=(str(tmp_path / "libs"),)) == (
        lib.resolve()
    )


def test_cache_entry_that_does_not_exist_is_ignored(tmp_path):
    lib = touch(tmp_path / "libs" / "liby.so.1")
    cache = {"liby.so.1": str(tmp_path / "gone" / "liby.so.1")}

    assert find_library("liby.so.1", cache, dirs=(str(tmp_path / "libs"),)) == (
        lib.resolve()
    )


def test_find_library_missing_is_none(tmp_path):
    assert find_library("libnope.so.9", {}, dirs=(str(tmp_path),)) is None


def test_ldconfig_cache_without_ldconfig_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))

    assert ldconfig_cache() == {}
