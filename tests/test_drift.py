import json
import shutil
import subprocess

import pytest

from xray import caplog
from xray.contract import ContractError, parse_contract
from xray.contractgen import from_graph, pin_capabilities
from xray.contractverbs import check_contract
from xray.drift import compare, drift, opened, profiles, stem
from xray.driftverbs import run_drift, run_log
from xray.evidence import build_evidence_graph

needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("readelf") is None, reason="needs gcc")

CLEAN = "int lz(int x){return x+1;}\n"
BACKDOORED = """
#include <stdlib.h>
static int impl(int x){return x+1;}
static void *resolve(void){return (void*)impl;}
int lz(int x) __attribute__((ifunc("resolve")));
__attribute__((constructor)) static void payload(void){ if (getenv("NEVER_SET_IN_TESTS")) system("true"); }
"""


def build(directory, source):
    (directory / "usr/lib").mkdir(parents=True)
    (directory / "src.c").write_text(source)
    subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,liblz.so.5", "-o", directory / "usr/lib/liblz.so.5",
                    directory / "src.c"], check=True)
    (directory / "src.c").unlink()
    return directory


def elf(**fields):
    base = {"kind": "elf", "sha256": "a", "needed": [], "classes": {}, "ifuncs": 0, "constructors": 0}
    base.update(fields)
    return base


def test_compare_reports_gains_and_losses():
    old = elf(needed=["libc.so.6"], classes={"net": ["socket"]})
    new = elf(sha256="b", needed=["libc.so.6", "libssl.so.3"], classes={"exec": ["execve"]}, ifuncs=1)

    changes = {(item["kind"], item["detail"]) for item in compare(old, new)}

    assert ("gain", "now uses exec: execve") in changes
    assert ("loss", "no longer uses net") in changes
    assert ("gain", "new library: libssl.so.3") in changes
    assert ("gain", "IFUNC resolvers: 0 -> 1") in changes


def test_rebuilt_libraries_with_new_hashes_are_not_gains():
    old = elf(needed=["libHSaeson-2.2.4.0-9J6qYuzRSLn7WcKE4MOZtk-ghc9.6.7.so", "libHSfgl-5.8.3.1-EgxYxOPkiDF4FbcwsEwYXI-ghc9.6.7.so"])
    new = elf(sha256="b", needed=["libHSaeson-2.2.5.0-CA4mvOJAYMJ0aDHQQisL9-ghc9.6.7.so", "libHSfgl-5.8.3.1-GgaQowQletEjKRaBiBlHg-ghc9.6.7.so"])

    assert [item["kind"] for item in compare(old, new)] == ["change", "change"]
    assert stem("libpcre2-8.so.0") == stem("libpcre2-8.so.0.16.1")


def test_drift_pairs_renamed_files_and_lists_gains_in_new_files():
    old = {"usr/lib/libx-1.0-AbCdEfGh12345678.so": elf()}
    new = {"usr/lib/libx-1.0-ZyXwVuTs87654321.so": elf(sha256="b"), "usr/bin/tool": elf(classes={"net": ["connect"]})}

    report = drift(old, new)

    assert report["added"] == [{"path": "usr/bin/tool", "kind": "elf"}]
    assert report["changed"][0]["changes"][0]["detail"].startswith("renamed from")
    assert [gain["detail"] for gain in report["gains"]] == ["new file uses net: connect"]


@needs_gcc
def test_drift_between_two_built_releases(tmp_path, capsys):
    old = build(tmp_path / "old", CLEAN)
    new = build(tmp_path / "new", BACKDOORED)

    assert run_drift([str(old), str(new), "--json", "--fail-on-gain"]) == 1
    details = {gain["detail"] for gain in json.loads(capsys.readouterr().out)["gains"]}

    assert "now uses shell: system" in details
    assert "IFUNC resolvers: 0 -> 1" in details
    assert any(detail.startswith("constructors run before main") for detail in details)


@needs_gcc
@pytest.mark.skipif(shutil.which("bsdtar") is None, reason="needs bsdtar")
def test_log_records_archives_and_detects_tampering(tmp_path, capsys):
    archives = []
    for version, source in (("1.0-1", CLEAN), ("1.1-1", BACKDOORED)):
        root = build(tmp_path / version, source)
        (root / ".PKGINFO").write_text(f"pkgname = lz\npkgver = {version}\narch = x86_64\n")
        archive = tmp_path / f"lz-{version}-x86_64.pkg.tar.zst"
        subprocess.run(["bsdtar", "--zstd", "-cf", archive, "-C", root, ".PKGINFO", "usr"], check=True)
        archives.append(str(archive))
    log = tmp_path / "log.jsonl"

    assert run_log(["add", *archives, "--log", str(log)]) == 0
    assert run_log(["add", *archives, "--log", str(log)]) == 0  # already logged: nothing added
    assert len(caplog.read_log(log)) == 2
    assert run_log(["verify", "--log", str(log)]) == 0
    capsys.readouterr()
    assert run_log(["history", "lz", "--log", str(log), "--json"]) == 0
    steps = json.loads(capsys.readouterr().out)["steps"]
    assert any(gain["detail"] == "now uses shell: system" for gain in steps[0]["gains"])

    lines = log.read_text().splitlines()
    first = json.loads(lines[0])
    first["version"] = "0.9-1"
    log.write_text(json.dumps(first) + "\n" + lines[1] + "\n")
    assert run_log(["verify", "--log", str(log)]) == 1
    assert "changed after it was written" in capsys.readouterr().out


def test_opened_reads_pkginfo_from_a_directory(tmp_path):
    (tmp_path / ".PKGINFO").write_text("pkgname = demo\npkgver = 2.0-1\n")
    tool = tmp_path / "usr/bin/tool"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\ncurl -s x\n")
    tool.chmod(0o755)

    with opened(tmp_path) as (_, _, files, meta):
        found = profiles(files)

    assert meta == {"pkgname": "demo", "pkgver": "2.0-1"}
    assert found["usr/bin/tool"]["classes"] == {"net": ["curl"]}


def test_capability_attributes_parse_and_reject_bad_values():
    contract = parse_contract("xray-contract 1\nprogram /a\n[load]\n/usr/lib/libz.so caps=- ifuncs=0 ctors=2  # x\n")
    entry = contract.sections["load"][0]

    assert (entry.attr("caps"), entry.attr("ctors")) == ("-", "2")
    assert parse_contract(contract.render()).sections["load"][0] == entry
    for bad in ("caps=magic", "ifuncs=many", "color=red"):
        with pytest.raises(ContractError):
            parse_contract(f"xray-contract 1\nprogram /a\n[load]\n/usr/lib/libz.so {bad}\n")
    with pytest.raises(ContractError, match="no attributes"):
        parse_contract("xray-contract 1\nprogram /a\n[read]\n/etc/x caps=-\n")


@needs_gcc
def test_check_flags_a_library_that_gains_capabilities_under_the_same_name(tmp_path):
    lib = build(tmp_path / "v1", CLEAN) / "usr/lib/liblz.so.5"
    (tmp_path / "app.c").write_text("int lz(int); int main(void){return lz(1) - 2;}\n")
    app = tmp_path / "app"
    subprocess.run(["gcc", "-o", app, tmp_path / "app.c", f"-L{lib.parent}", "-l:liblz.so.5",
                    f"-Wl,-rpath,{lib.parent}"], check=True)
    contract = pin_capabilities(from_graph(build_evidence_graph(str(app), packages=False)))

    assert check_contract(contract, build_evidence_graph(str(app), packages=False))["breaches"] == []

    replacement = build(tmp_path / "v2", BACKDOORED) / "usr/lib/liblz.so.5"
    shutil.copy(replacement, lib)
    breaches = check_contract(contract, build_evidence_graph(str(app), packages=False))["breaches"]
    details = " | ".join(item["detail"] for item in breaches)

    assert "now uses shell (system)" in details
    assert "IFUNC resolvers: 1 now" in details


def test_search_path_version_bumps_are_changes_not_gains():
    old = elf(runpath="/usr/lib/perl5/5.42/core_perl/CORE:$ORIGIN/")
    bumped = elf(sha256="b", runpath="/usr/lib/perl5/5.44/core_perl/CORE:$ORIGIN")
    widened = elf(sha256="c", runpath="/usr/lib/perl5/5.44/core_perl/CORE:/build/src")

    assert [item["kind"] for item in compare(old, bumped)] == ["change"]
    assert [item["kind"] for item in compare(old, widened)] == ["gain"]
