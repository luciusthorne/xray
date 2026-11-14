import os

from xray import android, contract


def _which(available):
    return lambda name: available.get(name)


def test_binutil_prefers_the_plain_name(monkeypatch, tmp_path):
    monkeypatch.setattr(android.shutil, "which", _which({"readelf": "/usr/bin/readelf", "greadelf": "/x/greadelf"}))
    assert android.binutil("readelf") == "readelf"


def test_binutil_falls_back_to_gnu_g_prefix(monkeypatch):
    monkeypatch.setattr(android.shutil, "which", _which({"greadelf": "/p/bin/greadelf"}))
    assert android.binutil("readelf") == "/p/bin/greadelf"
    assert android.binutil("nm") == "nm"  # neither installed: the plain name, so errors read naturally


def test_objdump_prefers_gnu_over_llvm(monkeypatch, tmp_path):
    llvm = tmp_path / "llvm-objdump"
    llvm.write_text("")
    plain = tmp_path / "objdump"
    plain.symlink_to(llvm)
    monkeypatch.setattr(android.shutil, "which", _which({"objdump": str(plain), "gobjdump": "/p/bin/gobjdump"}))
    assert android.binutil("objdump") == "/p/bin/gobjdump"

    monkeypatch.setattr(android.shutil, "which", _which({"objdump": str(plain)}))
    assert android.binutil("objdump") == "objdump"  # only LLVM's: use it


def test_library_dirs_put_termux_lib_first(monkeypatch, tmp_path):
    prefix = tmp_path / "usr"
    (prefix / "lib").mkdir(parents=True)
    monkeypatch.setattr(android, "prefix", lambda: str(prefix))
    monkeypatch.setattr(android, "system_library_dirs", lambda elf_class=64: ("/system/lib64",))
    assert android.library_dirs() == (f"{prefix}/lib", "/system/lib64")


def test_prefix_comes_from_termux_environment(monkeypatch, tmp_path):
    termux = tmp_path / "com.termux" / "files" / "usr"
    termux.mkdir(parents=True)
    monkeypatch.setenv("PREFIX", str(termux))
    assert android.prefix() == str(termux)
    monkeypatch.setenv("PREFIX", "/usr")
    assert android.prefix() in (None, android.TERMUX_PREFIX)


def test_android_baseline_only_on_android():
    on_android = android.is_android()
    assert ("/dev/__properties__/**" in contract.BASELINE_READ) == on_android


def test_enforce_allows_android_preloads(monkeypatch, tmp_path):
    from xray import enforce

    preload = tmp_path / "libtermux-exec.so"
    preload.write_text("")
    monkeypatch.setenv("LD_PRELOAD", f"{preload}:/missing.so")
    monkeypatch.setattr(android, "is_android", lambda: True)
    assert enforce._preloaded() == [str(preload)]
    monkeypatch.setattr(android, "is_android", lambda: False)
    assert enforce._preloaded() == []
    assert os.environ["LD_PRELOAD"].startswith(str(preload))
