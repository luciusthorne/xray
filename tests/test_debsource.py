"""Debian source from sources.debian.org, and Debian's relative build paths."""

from xray import debsource
from xray.codemap import _collapse_repeat


def test_candidates_drop_the_build_directory_and_refuse_escapes():
    assert debsource.candidates("./debian/build/src/./debian/build/src/tool_main.c")[-2:] == ["src/tool_main.c", "tool_main.c"]
    assert debsource.candidates("/build/reproducible-path/curl-8.14.1/lib/url.c")[0] == "lib/url.c"
    assert debsource.candidates("../../etc/passwd") == []


def test_source_file_tries_suffixes_and_caches(tmp_path, monkeypatch):
    monkeypatch.setenv("XRAY_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(debsource, "source_package", lambda binary: ("curl", "8.14.1-2+deb13u7"))
    debsource._MISSES.clear()
    asked = []

    def fetch(url):
        asked.append(url)
        if url.endswith("/main/c/curl/8.14.1-2+deb13u7/src/tool_main.c"):
            return b"int main(void) { return 0; }\n"
        raise OSError("404")

    found = debsource.source_file("/usr/bin/curl", "debian/build/src/tool_main.c", fetch=fetch)
    assert found.read_text().startswith("int main")
    assert asked[-1].endswith("/src/tool_main.c") and len(asked) == 3  # debian/build/src/.., build/src/.., src/..
    assert debsource.source_file("/usr/bin/curl", "debian/build/src/tool_main.c",
                                 fetch=lambda url: (_ for _ in ()).throw(AssertionError("cached"))) == found


def test_library_packages_use_the_lib_prefix():
    assert debsource._prefix("libcurl3") == "libc" and debsource._prefix("curl") == "c"


def test_collapse_only_relative_multi_folder_repeats():
    assert _collapse_repeat("debian/build/src/debian/build/src/x.c") == "debian/build/src/x.c"
    assert _collapse_repeat("/usr/src/debug/grep/grep/src/grep.c") == "/usr/src/debug/grep/grep/src/grep.c"
    assert _collapse_repeat("lib/lib/x.c") == "lib/lib/x.c"
