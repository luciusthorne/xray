import shutil
import subprocess

import pytest

from xray.elfscan import parse_search_paths, scan_elf
from xray.evidence import build_evidence_graph
from xray.libresolve import (
    expand_tokens,
    parse_ldconfig_entries,
    resolve_library,
    search_path_risks,
)

DYNAMIC = """
 0x0000000000000001 (NEEDED)             Shared library: [libf.so]
 0x000000000000000f (RPATH)              Library rpath: [$ORIGIN/../lib::/opt/x]
 0x000000006ffffffb (FLAGS_1)            Flags: NOW NODEFLIB
"""


def lib(directory, name="libf.so"):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b"\x7fELF")
    return path


def test_search_paths_are_parsed_with_empty_entries():
    assert parse_search_paths(DYNAMIC) == (("$ORIGIN/../lib", "", "/opt/x"), (), True)


def test_origin_is_expanded():
    assert expand_tokens("$ORIGIN/../lib:${ORIGIN}", "/a/bin") == "/a/bin/../lib:/a/bin"


def test_rpath_comes_before_ld_library_path(tmp_path):
    first = lib(tmp_path / "rpath")
    lib(tmp_path / "env")

    found = resolve_library("libf.so", tmp_path, rpath=[str(tmp_path / "rpath")], entries={},
                            environ={"LD_LIBRARY_PATH": str(tmp_path / "env")})

    assert (found.path, found.method) == (first.resolve(), "rpath")


def test_runpath_disables_rpath_and_comes_after_ld_library_path(tmp_path):
    lib(tmp_path / "rpath")
    lib(tmp_path / "run")
    env = lib(tmp_path / "env")

    found = resolve_library("libf.so", tmp_path, rpath=[str(tmp_path / "rpath")],
                            runpath=[str(tmp_path / "run")], entries={},
                            environ={"LD_LIBRARY_PATH": str(tmp_path / "env")})

    assert (found.path, found.method) == (env.resolve(), "LD_LIBRARY_PATH")


def test_setuid_programs_ignore_ld_library_path(tmp_path):
    lib(tmp_path / "env")
    run = lib(tmp_path / "run")

    found = resolve_library("libf.so", tmp_path, runpath=[str(tmp_path / "run")], entries={},
                            environ={"LD_LIBRARY_PATH": str(tmp_path / "env")}, secure=True)

    assert found.path == run.resolve()


def test_ldconfig_entries_for_the_other_word_size_are_skipped(tmp_path):
    wide = lib(tmp_path / "lib64")
    narrow = lib(tmp_path / "lib32")
    entries = parse_ldconfig_entries(
        f"\tlibf.so (libc6) => {narrow}\n\tlibf.so (libc6,x86-64) => {wide}\n"
    )

    assert resolve_library("libf.so", tmp_path, entries=entries, environ={}).path == wide.resolve()
    assert resolve_library("libf.so", tmp_path, entries=entries, environ={}, elf_class=32).path == narrow.resolve()


def test_nodefaultlib_skips_the_cache(tmp_path):
    cached = lib(tmp_path / "cache")
    entries = {"libf.so": [("libc6,x86-64", str(cached))]}

    found = resolve_library("libf.so", tmp_path, entries=entries, environ={}, nodeflib=True)

    assert found.path is None


def test_risky_search_path_entries(tmp_path):
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    open_dir.chmod(0o777)

    risks = search_path_risks(["", "lib", str(open_dir), str(open_dir / "missing"), "/usr/lib"], tmp_path,
                              "RUNPATH", owner_uid=open_dir.stat().st_uid)

    assert len(risks) == 4
    assert risks[0].startswith("empty RUNPATH entry")
    assert risks[1].startswith("relative RUNPATH entry `lib`")
    assert "writable by other users" in risks[2]
    assert "does not exist, and its parent" in risks[3]


@pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("readelf") is None, reason="needs gcc and readelf")
def test_compiled_binary_resolves_through_its_rpath(tmp_path):
    (tmp_path / "f.c").write_text("int f(void){return 1;}\n")
    (tmp_path / "m.c").write_text("int f(void); int main(void){return f();}\n")
    (tmp_path / "lib").mkdir()
    (tmp_path / "bin").mkdir()
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", tmp_path / "lib/libf.so", tmp_path / "f.c"], check=True)
    subprocess.run(
        ["gcc", "-o", tmp_path / "bin/app", tmp_path / "m.c", f"-L{tmp_path / 'lib'}", "-lf",
         "-Wl,-rpath,$ORIGIN/../lib:", "-Wl,--disable-new-dtags"],
        check=True,
    )

    assert scan_elf(tmp_path / "bin/app").rpath == ("$ORIGIN/../lib", "")

    graph = build_evidence_graph(str(tmp_path / "bin/app"), packages=False)
    link = graph.links[("soname:libf.so", str((tmp_path / "lib/libf.so").resolve()), "resolves_to")]

    assert link.evidence[0].method == "rpath"
    assert any("empty RPATH entry" in risk["message"] for risk in graph.risks)
