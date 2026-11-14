import io
import tarfile
from pathlib import Path

import pytest

from xray import haskell


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XRAY_CACHE_DIR", str(tmp_path / "cache"))
    haskell._load.cache_clear()
    haskell._members.cache_clear()
    haskell._read_package.cache_clear()


@pytest.mark.parametrize("encoded, decoded", [
    ("ShellCheckziAnalytics", "ShellCheck.Analytics"),
    ("PathszuShellCheck", "Paths_ShellCheck"),
    ("zdwzdserror", "$w$serror"),
    ("ShellCheckzm0zi11zi0zm39iAT3", "ShellCheck-0.11.0-39iAT3"),
    ("ZLzlzpzgZR", "(<+>)"),
    ("ZC", ":"),
    ("Z3T", "(,,)"),
    ("Z2H", "(#,#)"),
    ("z7eU", "~"),
    ("zz", "z"),
    ("plain", "plain"),
])
def test_zdecode(encoded, decoded):
    assert haskell.zdecode(encoded) == decoded


def test_split_symbol_and_unit():
    unit, module, name, kind = haskell.split_symbol(
        "ShellCheckzm0zi11zi0zm39iAT3MqTiu2cUym0mKI03_ShellCheckziAnalytics_checkForInLs_info")
    assert (module, name, kind) == ("ShellCheck.Analytics", "checkForInLs", "info")
    assert haskell.unit_package(unit) == ("ShellCheck", "0.11.0")
    assert haskell.unit_package("base") == ("base", None)
    assert haskell.split_symbol("ShellCheckzm0_ShellCheckziAST_TzuForIn_con_info")[2:] == ("T_ForIn", "con_info")
    assert haskell.split_symbol("stg_ap_0_fast") is None
    assert haskell.split_symbol("__bss_start") is None


def test_generated_names_fold_into_their_binding():
    names = {"check", "runTests", "warn"}
    assert haskell.binding_of("$wcheck", names) == "check"
    assert haskell.binding_of("runTests6279", names) == "runTests"
    assert haskell.binding_of("runTests_x1178", names) == "runTests"
    assert haskell.binding_of("check1", names) == "check"
    assert haskell.binding_of("check1", {"other"}) == "check1"  # no base: a real name


def test_read_package_from_symbols(monkeypatch, tmp_path):
    library = tmp_path / "libHSDemo-1.2-abc123-ghc9.6.7.so"
    library.write_bytes(b"\x7fELF")
    prefix = "Demozm1zi2zmabc123_DemoziCore_"
    symbols = [prefix + name for name in (
        "run_info", "run_closure", "zdwrun_info", "run3_closure", "helper_info", "runzustr4_bytes",
        "Box_con_info", "zdfShowBox_closure", "zqNoPipe_closure",
    )]
    monkeypatch.setattr(haskell, "_dynamic_symbols", lambda path: symbols)

    package = haskell.read_package(library)

    assert (package.name, package.version) == ("Demo", "1.2")
    assert sorted(package.modules["Demo.Core"]) == ["helper", "run"]
    assert package.constructors["Demo.Core"] == {"Box"}
    assert package.generated >= 4


SOURCE = '''module Demo.Core (run, helper) where

import Demo.Util

-- | Run it.
run :: Int -> Int
run 0 = 0
run n
  | n > 1 = helper n + twice n  -- calls helper
  | otherwise = go n
  where
    go x = x

helper :: Int -> Int
helper = (+ 1)

{- a block comment naming run -}
text = "run helper"

return []
'''

UTIL = '''module Demo.Util where

twice :: Int -> Int
twice x = x * 2

unused = twice 3
'''


def test_definitions_signatures_equations_and_splices():
    spans = haskell.definitions(SOURCE.splitlines())

    assert spans["run"] == (6, 12)
    assert spans["helper"] == (14, 15)
    assert "return" not in spans  # a Template Haskell splice, not a definition
    assert "text" in spans


def test_blank_removes_comments_and_strings():
    clean = haskell.blank(['x = "run" -- run', "{- run", "run -}", "y = a --> b", "c = 'r'"])
    assert "run" not in " ".join(clean[:3])
    assert clean[3] == "y = a --> b"


def make_tarball(files, root):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            handle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.fixture
def demo(tmp_path):
    data = make_tarball({"Demo.cabal": "name: Demo\nexecutable demo\n    main-is: Main.hs\n"
                                 "    hs-source-dirs: app\n",
                                 "src/Demo/Core.hs": SOURCE, "src/Demo/Util.hs": UTIL,
                                 "app/Main.hs": "main = print (run 3)\n"}, "Demo-1.2")
    package = haskell.Package("Demo", "1.2", tmp_path / "libHSDemo-1.2-x-ghc9.6.7.so",
                              modules={"Demo.Core": {"run": "info", "helper": "info"},
                                       "Demo.Util": {"twice": "info", "unused": "info"}})
    prog = haskell.Program(tmp_path / "demo", "9.6.7", [package], [], ["libHSrts-1.0.2-ghc9.6.7.so"])
    calls = []

    def fetch(url):
        calls.append(url)
        return data

    return prog, fetch, calls


def test_function_source_from_hackage(demo):
    prog, fetch, calls = demo

    shown = haskell.code_lines(prog, "run", fetch)

    assert "Demo.Core.run (Demo 1.2): Demo-1.2/src/Demo/Core.hs, lines 6–12" in shown[0]
    assert any("run n" in line for line in shown)
    assert calls == ["https://hackage.haskell.org/package/Demo-1.2/Demo-1.2.tar.gz"]
    haskell.code_lines(prog, "helper", fetch)
    assert len(calls) == 1  # the archive is cached


def test_module_and_main(demo):
    prog, fetch, _ = demo

    module = haskell.code_lines(prog, "Demo.Util", fetch)
    assert module[0] == "Demo.Util (Demo 1.2)"
    assert any("twice x = x * 2" in line for line in module)

    main = haskell.code_lines(prog, "Main", fetch)
    assert "Demo-1.2/app/Main.hs" in main[0]


def test_callgraph_follows_imports_and_skips_local_bindings(demo):
    prog, fetch, _ = demo

    text = "\n".join(haskell.callgraph_lines(prog, "run", fetch))

    assert "→ helper  (line 14" in text
    assert "→ twice  (Demo.Util, line 3" in text
    assert "→ go" not in text  # a where binding, not a call out

    callers = "\n".join(haskell.callgraph_lines(prog, "twice", fetch))
    assert "← run  (Demo.Core, line 9)" in callers
    assert "← unused  (line 6)" in callers


def test_not_haskell(monkeypatch, tmp_path):
    binary = tmp_path / "tool"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setattr(haskell, "_needed", lambda path: ["libc.so.6"])
    assert haskell.program(binary) is None


def test_program_splits_own_code_from_libraries(monkeypatch, tmp_path):
    own = tmp_path / "libHSDemo-1.2-x-ghc9.6.7.so"
    dep = tmp_path / "libHSaeson-2.2-y-ghc9.6.7.so"
    for library in (own, dep):
        library.write_bytes(b"\x7fELF")
    binary = tmp_path / "demo"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setattr(haskell, "_needed", lambda path: [
        "libc.so.6", "libHSrts-1.0.2-ghc9.6.7.so", "libHSbase-4.18.3.0-ghc9.6.7.so", own.name, dep.name])
    monkeypatch.setattr(haskell, "_find", lambda soname, cache: tmp_path / soname)
    monkeypatch.setattr(haskell, "_dynamic_symbols", lambda path: [])
    monkeypatch.setattr("xray.provenance.package_of", lambda path: None)

    prog = haskell.program(binary)

    assert [p.name for p in prog.own] == ["Demo"]
    assert [p.name for p in prog.dependencies] == ["aeson"]
    assert len(prog.boot) == 2
    assert Path(prog.path) == binary
