import shutil
import subprocess

import pytest

from xray.fingerprint import _go_buildinfo, fingerprint, toolchain_lines

gcc = pytest.mark.skipif(not shutil.which("gcc"), reason="gcc is required")


def _uvarint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def go_section(version, modinfo):
    sentinel = b"0" * 15 + b"\n"
    info = sentinel + modinfo.encode() + sentinel[:-1] + b"\n"
    header = b"\xff Go buildinf:" + bytes([8, 2]) + bytes(16)
    return header + _uvarint(len(version)) + version.encode() + _uvarint(len(info)) + info


MODINFO = (
    "path\texample.com/tool\n"
    "mod\texample.com/tool\tv1.2.3\th1:abc=\n"
    "dep\tgolang.org/x/sys\tv0.30.0\th1:def=\n"
    "dep\texample.com/old\tv1.0.0\n"
    "=>\texample.com/new\tv1.1.0\th1:ghi=\n"
    "build\tCGO_ENABLED=0\n"
)


def compile_c(tmp_path, source, compiler="gcc", suffix=".c"):
    path = tmp_path / ("prog" + suffix)
    path.write_text(source, encoding="utf-8")
    binary = tmp_path / "prog"
    subprocess.run([compiler, str(path), "-o", str(binary)], check=True, capture_output=True)
    return binary


def test_go_buildinfo_is_decoded():
    version, modinfo = _go_buildinfo(go_section("go1.24.1", MODINFO))

    assert version == "go1.24.1"
    assert modinfo.startswith("path\texample.com/tool")


@gcc
def test_go_binary_reports_module_dependencies_and_settings(tmp_path):
    data = ", ".join(str(b) for b in go_section("go1.24.1", MODINFO))
    binary = compile_c(
        tmp_path,
        "__attribute__((section(\".go.buildinfo\"), used))\n"
        f"static const unsigned char info[] = {{{data}}};\n"
        "int main(void) { return 0; }\n",
    )

    found = fingerprint(binary)

    assert found.language == "Go"
    assert found.toolchain == "go1.24.1"
    assert found.module == "example.com/tool v1.2.3"
    assert found.dependencies == (
        "golang.org/x/sys v0.30.0",
        "example.com/old v1.0.0 => example.com/new v1.1.0",
    )
    assert found.settings == ("CGO_ENABLED=0",)


@gcc
def test_rust_markers_and_crate_paths(tmp_path):
    binary = compile_c(
        tmp_path,
        'const char *a = "RUST_BACKTRACE";\n'
        'const char *b = "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.200/src/de.rs";\n'
        'const char *c = "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aho-corasick-1.1.4/src/dfa.rs";\n'
        "int main(void) { return a[0] + b[0] + c[0]; }\n",
    )

    found = fingerprint(binary)

    assert found.language == "Rust"
    assert found.dependencies == ("aho-corasick 1.1.4", "serde 1.0.200")


@gcc
def test_c_binary_reports_compiler(tmp_path):
    found = fingerprint(compile_c(tmp_path, "int main(void) { return 0; }\n"))

    assert found.language == "C"
    assert any("GCC" in item or "clang" in item for item in found.compilers)


@pytest.mark.skipif(not shutil.which("g++"), reason="g++ is required")
def test_cpp_binary(tmp_path):
    binary = compile_c(
        tmp_path,
        "#include <string>\nint main() { std::string s(\"x\"); return (int)s.size() - 1; }\n",
        compiler="g++", suffix=".cpp",
    )

    assert fingerprint(binary).language == "C++"


def test_non_elf_files_are_unknown(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("go1.22 RUST_BACKTRACE", encoding="utf-8")

    assert fingerprint(path).language == "unknown"
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    assert fingerprint(empty).language == "unknown"


def test_long_lists_are_capped(tmp_path, monkeypatch):
    import xray.fingerprint as fp

    deps = tuple(f"dep{n} v1" for n in range(70))
    monkeypatch.setattr(fp, "fingerprint", lambda p: fp.Fingerprint("Go", "go1", dependencies=deps))

    lines = toolchain_lines("x", limit=60)

    assert "Dependencies (70):" in lines
    assert lines[-1] == "- ... and 10 more"


@pytest.mark.skipif(not shutil.which("go"), reason="go is required")
def test_real_go_build(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/realtool\n\ngo 1.21\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(tmp_path),
        "GOCACHE": str(tmp_path / "cache"), "GOPATH": str(tmp_path / "gopath"),
        "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0",
    }
    result = subprocess.run(
        [shutil.which("go"), "build", "-o", "realtool", "."],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        pytest.skip(f"go build failed: {result.stderr.strip()[:200]}")

    found = fingerprint(tmp_path / "realtool")

    assert found.language == "Go"
    assert found.toolchain.startswith("go1.")
    assert found.module.startswith("example.com/realtool")
    assert "CGO_ENABLED=0" in found.settings


@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc is required")
def test_real_rustc_build(tmp_path):
    (tmp_path / "main.rs").write_text("fn main() { println!(\"hi\"); }\n", encoding="utf-8")
    result = subprocess.run(
        [shutil.which("rustc"), "main.rs", "-o", "realtool"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        pytest.skip(f"rustc failed: {result.stderr.strip()[:200]}")

    found = fingerprint(tmp_path / "realtool")

    assert found.language == "Rust"
    assert found.toolchain.startswith("rustc ")
