import io
import shutil
import subprocess
import tarfile

import pytest

from xray import pachook
from xray.contract import parse_contract

needs_tools = pytest.mark.skipif(shutil.which("bsdtar") is None or shutil.which("gcc") is None,
                                 reason="needs bsdtar and gcc")


def library(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    src = path.parent / "src.c"
    src.write_text(source)
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", path, src], check=True)
    src.unlink()


@pytest.fixture
def system(tmp_path):
    installed = tmp_path / "installed" / "usr/lib/libdemo.so.1.0"
    library(installed, "int f(void){return 1;}\n")
    root = tmp_path / "pkgroot"
    library(root / "usr/lib/libdemo.so.1.1", '#include <stdlib.h>\nint f(void){return system("true");}\n')
    (root / ".PKGINFO").write_text("pkgname = demo\npkgver = 1.1-1\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    subprocess.run(["bsdtar", "--zstd", "-cf", cache / "demo-1.1-1-x86_64.pkg.tar.zst", "-C", root, ".PKGINFO", "usr"],
                   check=True)
    sync = tmp_path / "db" / "sync"
    sync.mkdir(parents=True)
    with tarfile.open(sync / "core.db", "w:gz") as archive:
        data = b"%FILENAME%\ndemo-1.1-1-x86_64.pkg.tar.zst\n\n%NAME%\ndemo\n\n%VERSION%\n1.1-1\n"
        info = tarfile.TarInfo("demo-1.1-1/desc")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    conf = {"CacheDir": [str(cache)], "DBPath": str(tmp_path / "db")}

    def files(name, everything=False):
        return [str(installed)] if name == "demo" else []

    return conf, files, installed


@needs_tools
def test_report_mode_shows_strong_gains_without_blocking(system, tmp_path):
    conf, files, _ = system
    lines, block = pachook.check_targets(["demo", "other"], conf=conf, config={"mode": "report", "allow": set()},
                                         contracts_dir=str(tmp_path / "none"), installed=files)

    assert lines[0].startswith("[STRONG] demo 1.1-1")
    assert any("uses shell: system" in line for line in lines)
    assert block is False


@needs_tools
def test_block_mode_blocks_unless_allowed(system, tmp_path):
    conf, files, _ = system
    blocked = pachook.check_targets(["demo"], conf=conf, config={"mode": "block", "allow": set()},
                                    contracts_dir=str(tmp_path / "none"), installed=files)
    allowed = pachook.check_targets(["demo"], conf=conf, config={"mode": "block", "allow": {"demo"}},
                                    contracts_dir=str(tmp_path / "none"), installed=files)

    assert blocked[1] is True and "XRAY blocked the upgrade of demo" in blocked[0][-2]
    assert allowed[1] is False


@needs_tools
def test_contract_pins_are_rechecked_against_the_new_version(system, tmp_path):
    conf, files, installed = system
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "app.contract").write_text(
        f"xray-contract 1\nprogram /usr/bin/app\n[load]\n{installed} caps=- ifuncs=0 ctors=9\n")
    # the archive installs to /usr/lib; map the contract entry to the archive path for the check
    contract = parse_contract((contracts / "app.contract").read_text().replace(str(installed), "/usr/lib/libdemo.so.1.0"))
    breaches = pachook.pin_breaches(contract, {"usr/lib/libdemo.so.1.1": {"classes": {"shell": ["system"]},
                                                                           "ifuncs": 0, "constructors": 1}})

    assert breaches == ["/usr/lib/libdemo.so.1.0: would use shell (system); the contract allows caps=-"]
    lines, _ = pachook.check_targets(["demo"], conf=conf, config={"mode": "report", "allow": set()},
                                     contracts_dir=str(contracts), installed=files)
    assert lines[0].startswith("[STRONG] demo")


def test_config_is_read(tmp_path):
    path = tmp_path / "hook.conf"
    path.write_text("mode = block  # stop\nallow = linux nvidia\n")

    assert pachook.read_config(path) == {"mode": "block", "allow": {"linux", "nvidia"}, "policy": None}
    assert pachook.read_config(tmp_path / "missing") == {"mode": "report", "allow": set(), "policy": None}
