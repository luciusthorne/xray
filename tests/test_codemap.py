"""Code map of compiled programs: names, files, lines and source for any DWARF language."""

import io
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from xray import codemap
from xray.codemap import _base, body_end, crate_source, origin, rust_std_source


@pytest.mark.parametrize("name, base", [
    ("<rg::search::SearchWorker<termcolor::Buffer>>::search_reader::<grep_cli::Reader>", "rg::search::SearchWorker::search_reader"),
    ("anyhow::error::object_downcast::<&str>", "anyhow::error::object_downcast"),
    ("<alloc::vec::Vec<T> as core::ops::drop::Drop>::drop", "alloc::vec::Vec::drop"),
    ("Runner::_runner(void*) [clone .lto_priv.0]", "Runner::_runner"),
    ("main", "main"),
    # C++ lambdas keep their place instead of folding into the function around them
    (("DeviceTestingArea::DeviceTestingArea(GladeSearchpath*, _GtkBox*, Settings*)::{lambda(_GtkButton*, void*)#2}"
     "::_FUN(_GtkButton*, void*)"), "DeviceTestingArea::DeviceTestingArea::{lambda#2}"),
    (("CustomExportJob::showDialogAndRun()::{lambda()#1}::operator()() const::{lambda()#1}::operator()() const "
     "[clone .cold]"), "CustomExportJob::showDialogAndRun::{lambda#1}::{lambda#1}"),
    (("std::_Function_handler<void (std::filesystem::__cxx11::path, bool), Control::missingPdfDialogResponseHandler("
     "std::filesystem::__cxx11::path, int)::{lambda(std::filesystem::__cxx11::path, bool)#1}>::_M_invoke("
     "std::_Any_data const&, std::filesystem::__cxx11::path&&, bool&&)"),
     "Control::missingPdfDialogResponseHandler::{lambda#1} (std::function)"),
    ("void xoj::util::destroy_cb<Palette::parseErrorDialog(std::exception const&) const::{lambda()#1}, 1>(void*)",
     "xoj::util::destroy_cb"),
    ("main::{lambda(int)#1}::operator()(int) const", "main::{lambda#1}"),
    ("rg::main::{{closure}}", "rg::main::{{closure}}"),
])
def test_base_names(name, base):
    assert _base(name) == base


@pytest.mark.parametrize("path, expected", [
    ("/usr/src/debug/rust/rustc-1.97.0-src/library/core/src/fmt/mod.rs", ("standard library", "Rust standard library")),
    ("/rustc/0123456789abcdef0123456789abcdef01234567/library/std/src/io.rs", ("standard library", "Rust standard library")),
    ("/build/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/anyhow-1.0.103/src/error.rs", ("dependency", "anyhow 1.0.103")),
    ("/usr/include/c++/15.2.1/bits/basic_string.h", ("standard library", "C++ standard library")),
    ("/usr/include/stdio.h", ("system headers", "system headers")),
    ("/usr/src/debug/grep/grep/src/grep.c", ("program", None)),
])
def test_origin(path, expected):
    assert origin(path) == expected


RUST = '''fn tricky<'a>(s: &'a str) -> char {
    let open = '{';
    let quote = '\\'';
    let raw = r#"}"# ;
    // } in a comment
    /* } in a block */
    if s.is_empty() { return '}'; }
    'outer: loop { break 'outer; }
    open
}
fn after() {}
'''


def test_body_end_rust_lifetimes_chars_raw_strings_and_comments():
    lines = RUST.splitlines()
    assert body_end(lines, 1, "rust") == 10


def test_body_end_c_and_go():
    c = 'int f(void) {\n  char c = \'{\';\n  puts("}");\n  return 0;\n}\n'.splitlines()
    assert body_end(c, 1, "c") == 5
    go = 'func f() {\n\ts := `}`\n\t_ = s\n}\n'.splitlines()
    assert body_end(go, 1, "go") == 4


def _tar(members, mode):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_crate_source_extracts_one_member(tmp_path, monkeypatch):
    monkeypatch.setenv("XRAY_CACHE_DIR", str(tmp_path))
    urls = []
    archive = _tar({"anyhow-1.0.103/src/error.rs": b"fn x() {}\n", "anyhow-1.0.103/src/lib.rs": b""}, "w:gz")

    def fetch(url):
        urls.append(url)
        return archive

    file = "/build/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/anyhow-1.0.103/src/error.rs"
    got = crate_source(file, fetch=fetch)
    assert got.read_text() == "fn x() {}\n"
    assert urls == ["https://static.crates.io/crates/anyhow/anyhow-1.0.103.crate"]
    assert crate_source(file, fetch=lambda url: pytest.fail("cached")) == got
    assert crate_source(file.replace("src/error.rs", "../../etc/passwd"), fetch=fetch) is None


def test_rust_std_source_uses_the_exact_version(tmp_path, monkeypatch):
    monkeypatch.setenv("XRAY_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(codemap, "_local_rust_library", lambda version: None)
    member = "rust-src-1.97.0/rust-src/lib/rustlib/src/rust/library/core/src/fmt/mod.rs"
    archive = _tar({member: b"pub fn write() {}\n"}, "w:xz")
    urls = []
    file = "/usr/src/debug/rust/rustc-1.97.0-src/library/core/src/fmt/mod.rs"
    got = rust_std_source(file, fetch=lambda url: urls.append(url) or archive)
    assert got.read_text() == "pub fn write() {}\n"
    assert urls == ["https://static.rust-lang.org/dist/rust-src-1.97.0.tar.xz"]


PROGRAM = r'''#include <stdio.h>

static int helper(int x)
{
    const char *brace = "}";
    return x + (brace[0] == '}');
}

int main(void)
{
    printf("%d\n", helper(1));
    return 0;
}
'''


@pytest.mark.skipif(not all(shutil.which(t) for t in ("cc", "addr2line", "c++filt", "readelf")),
                    reason="needs cc and binutils")
def test_code_map_of_a_local_program_with_debug_info(tmp_path):
    source = tmp_path / "tool.c"
    source.write_text(PROGRAM)
    binary = tmp_path / "tool"
    subprocess.run(["cc", "-g", "-O0", "-o", str(binary), str(source)], check=True)

    cmap = codemap.code_map(binary, online=False)
    assert cmap is not None and cmap.via == "the binary's symbol table"
    names = {f.name: f for f in cmap.located()}
    assert names["main"].file == str(source) and names["main"].line == 10
    assert names["helper"].line == 4

    overview = "\n".join(codemap.overview_lines(cmap, "tool"))
    assert "Program: 1 file(s)" in overview

    view = codemap.function_view(cmap, "helper", "tool")
    assert view[1].endswith("tool.c:3 (source from this machine)")
    assert view[-1].strip().endswith("}") and "return x" in view[-2]

    listing = codemap.file_view(cmap, "tool.c", "tool")
    assert any(line.strip().endswith("main") for line in listing[:6])
    assert codemap.function_view(cmap, "nothing_here", "tool") is None


def test_template_return_type_is_dropped():
    assert _base("void Logger::error<char const*>(std::basic_string_view<char>)") == "Logger::error"


@pytest.mark.skipif(not all(shutil.which(t) for t in ("cc", "addr2line", "c++filt", "readelf", "objdump")),
                    reason="needs cc and binutils")
def test_callgraph_of_a_local_program(tmp_path):
    from xray.disasm import disasm_result

    source = tmp_path / "tool.c"
    source.write_text(PROGRAM)
    binary = tmp_path / "tool"
    subprocess.run(["cc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(source)], check=True)
    cmap = codemap.code_map(binary, online=False)
    found = disasm_result(binary)

    lines = codemap.callgraph_lines(cmap, found.calls, "tool", focus="main", indirect=found.indirect)
    text = "\n".join(lines)
    assert lines[0].startswith("main  (") and "tool.c:10" in lines[0]
    assert "→ helper  (tool.c:4)" in text
    assert "→ printf" in text and "shared library" in text

    back = "\n".join(codemap.callgraph_lines(cmap, found.calls, "tool", focus="helper"))
    assert "← main  (tool.c:10)" in back

    whole = "\n".join(codemap.callgraph_lines(cmap, found.calls, "tool"))
    assert "tool.c" in whole and "  main  (line 10)" in whole


def test_callgraph_merges_generic_copies():
    functions = [
        codemap.Function("a::run", "s_run", 1, 1, "/src/p/a.rs", 3),
        codemap.Function("a::Thing<u8>::go", "s_go1", 2, 1, "/src/p/a.rs", 9),
        codemap.Function("a::Thing<u16>::go", "s_go2", 3, 1, "/src/p/a.rs", 9),
    ]
    cmap = codemap.CodeMap(Path("/bin/x"), functions, "test",
                           files={"/src/p/a.rs": functions})
    lines = codemap.callgraph_lines(cmap, {"s_run": ("s_go1", "s_go2", "malloc@plt")}, "x", focus="a::run")
    text = "\n".join(lines)
    assert "→ a::Thing::go ×2" in text
    assert "→ malloc  (shared library)" in text
