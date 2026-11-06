import json
import shutil
import subprocess

import pytest

from xray.driftverbs import run_drift, run_explain
from xray.explain import call_sites, explain

needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("objdump") is None,
                               reason="needs gcc and objdump")

SOURCE = """#include <stdlib.h>
int helper(int x) { return x + 1; }
int run_hook(const char *command) {
    return system(command);
}
"""


def library(path, source, *flags):
    path.parent.mkdir(parents=True, exist_ok=True)
    src = path.parent / "lib.c"
    src.write_text(source)
    subprocess.run(["gcc", "-shared", "-fPIC", *flags, "-o", path, src], check=True)
    return path


@needs_gcc
def test_call_sites_come_with_function_and_line(tmp_path, monkeypatch):
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    path = library(tmp_path / "libx.so", SOURCE, "-g", "-O0")

    sites, how = explain(path, ["system"])

    assert how == "the binary's own debug information"
    assert [(site.symbol, site.function) for site in sites] == [("system", "run_hook")]
    assert sites[0].location.split(":")[1] == "4" and sites[0].location.split(":")[0].endswith("lib.c")


@needs_gcc
def test_plt_stubs_are_not_call_sites_and_missing_symbols_give_none(tmp_path):
    path = library(tmp_path / "libx.so", SOURCE, "-O0")

    assert [site.symbol for site in call_sites(path, ["system"])] == ["system"]
    assert call_sites(path, ["connect"]) == []


@needs_gcc
def test_stripped_binary_without_debuginfod_says_why(tmp_path, monkeypatch):
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    path = library(tmp_path / "libx.so", SOURCE, "-O0", "-s")

    sites, how = explain(path, ["system"])

    assert sites and sites[0].function is None
    assert how.startswith("stripped, and no debuginfod server is configured")


@needs_gcc
def test_drift_explain_attributes_new_call_classes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    library(tmp_path / "old" / "usr/lib/libx.so", "int run_hook(const char *c) { return 0; }\n", "-g")
    library(tmp_path / "new" / "usr/lib/libx.so", SOURCE, "-g")

    assert run_drift([str(tmp_path / "old"), str(tmp_path / "new"), "--explain", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["explained"][0]["detail"] == "now uses shell: system"
    assert report["explained"][0]["sites"][0]["function"] == "run_hook"
    assert run_explain([str(tmp_path / "new" / "usr/lib/libx.so"), "system"]) == 0
    assert "in run_hook" in capsys.readouterr().out
