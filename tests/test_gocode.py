"""Go programs: .gopclntab functions, path normalisation, origins and source fetching."""

import io
import shutil
import subprocess
import zipfile

import pytest

from xray import codemap, gocode
from xray.gocode import GoInfo


def test_readable_go_names():
    assert gocode.go_base("github.com/junegunn/fzf/src.(*Terminal).Loop") == "src.Terminal.Loop"
    assert gocode.go_base("slices.Sort[go.shape.int]") == "slices.Sort"
    assert gocode.go_base("main.main") == "main.main"


def test_origins():
    info = GoInfo("go1.27.2", "github.com/junegunn/fzf", "v0.74.5", None)
    assert gocode.origin("github.com/junegunn/fzf/src/core.go", info) == ("program", None)
    assert gocode.origin("golang.org/x/sys@v0.35.0/unix/syscall.go", info) == ("dependency", "golang.org/x/sys v0.35.0")
    assert gocode.origin("runtime/proc.go", info) == ("standard library", "Go standard library")
    assert gocode.origin("_cgo_gotypes.go", info)[0] == "standard library"


def test_paths_of_builds_without_trimpath_are_normalised():
    info = GoInfo("go1.27.3", "github.com/cli/cli/v2", "v2.103.3", None)
    files = {
        "/opt/go/1.27.3/x64/src/runtime/proc.go",
        "/opt/go/1.27.3/x64/src/net/http/transport.go",
        "/home/runner/go/pkg/mod/github.com/!burnt!sushi/toml@v1.4.0/decode.go",
        "/home/runner/work/cli/cli/cmd/gh/main.go",
        "/home/runner/work/cli/cli/pkg/cmd/root/root.go",
    }
    out = gocode.normalise_paths(files, info)
    assert out["/opt/go/1.27.3/x64/src/runtime/proc.go"] == "runtime/proc.go"
    assert out["/opt/go/1.27.3/x64/src/net/http/transport.go"] == "net/http/transport.go"
    assert out["/home/runner/go/pkg/mod/github.com/!burnt!sushi/toml@v1.4.0/decode.go"] == "github.com/BurntSushi/toml@v1.4.0/decode.go"
    assert out["/home/runner/work/cli/cli/cmd/gh/main.go"] == "github.com/cli/cli/v2/cmd/gh/main.go"
    assert gocode.escape_module("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


def _zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, data in members.items():
            bundle.writestr(name, data)
    return buffer.getvalue()


def test_source_from_the_module_proxy_and_the_go_repository(tmp_path, monkeypatch):
    monkeypatch.setenv("XRAY_CACHE_DIR", str(tmp_path))
    info = GoInfo("go1.27.2-X:nodwarf5", "github.com/junegunn/fzf", "v0.74.5+dirty", None)
    urls = []

    def fetch(url, limit=None):
        urls.append(url)
        if url.endswith("/golang.org/x/sys/@v/v0.35.0.zip"):
            return _zip({"golang.org/x/sys@v0.35.0/unix/syscall.go": b"package unix\n"})
        if url.endswith("/github.com/junegunn/fzf/@v/v0.74.5.zip"):
            return _zip({"github.com/junegunn/fzf@v0.74.5/main.go": b"package main\n"})
        if url == "https://raw.githubusercontent.com/golang/go/go1.27.2/src/runtime/proc.go":
            return b"package runtime\n"
        raise OSError(url)

    found, where = gocode.source("golang.org/x/sys@v0.35.0/unix/syscall.go", info, fetch)
    assert found.read_text() == "package unix\n" and where == "the Go module proxy"
    found, where = gocode.source("github.com/junegunn/fzf/main.go", info, fetch)
    assert found.read_text() == "package main\n" and "+dirty" in where
    found, where = gocode.source("runtime/proc.go", info, fetch)
    assert found.read_text() == "package runtime\n" and "go1.27.2" in where
    assert gocode.source("golang.org/x/sys@v0.35.0/../../etc/passwd", info, fetch)[0] is None


PROGRAM = """package main

import "fmt"

//go:noinline
func helper(x int) int {
	return x + 1
}

func main() {
	fmt.Println(helper(41))
}
"""


@pytest.mark.skipif(not (shutil.which("go") and shutil.which("objdump")), reason="needs go and objdump")
@pytest.mark.parametrize("flags", [["-trimpath"], []])
def test_real_go_binary(tmp_path, monkeypatch, flags):
    monkeypatch.setenv("GOFLAGS", "-mod=mod")
    monkeypatch.setenv("GOCACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("GOPATH", str(tmp_path / "gopath"))
    (tmp_path / "go.mod").write_text("module example.com/hello\n\ngo 1.21\n")
    (tmp_path / "main.go").write_text(PROGRAM)
    binary = tmp_path / "hello"
    subprocess.run(["go", "build", *flags, "-o", str(binary), "."], cwd=tmp_path, check=True,
                   env={**__import__("os").environ, "CGO_ENABLED": "0"})

    functions, info = gocode.go_functions(binary)
    assert info.module == "example.com/hello"
    by_name = {name: (address, file, line) for address, _size, name, file, line in functions}
    assert by_name["main.helper"][1:] == ("example.com/hello/main.go", 6)
    assert by_name["main.main"][2] == 10

    codemap._CACHE.clear()
    cmap = codemap.code_map(binary, online=False)
    from xray.disasm import disasm_result

    found = disasm_result(binary, table=[(f.address, f.size, f.symbol) for f in cmap.functions])
    assert "main.helper" in found.calls.get("main.main", ())  # addresses line up with the machine code
    text = "\n".join(codemap.callgraph_lines(cmap, found.calls, "hello", focus="main.main"))
    assert "→ main.helper  (main.go:6)" in text
