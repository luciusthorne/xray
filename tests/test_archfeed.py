import base64
import hashlib
import io
import json
import shutil
import subprocess
import tarfile

import pytest

from xray import archfeed
from xray.driftverbs import run_feed

needs_tools = pytest.mark.skipif(shutil.which("bsdtar") is None or shutil.which("gcc") is None,
                                 reason="needs bsdtar and gcc")


def make_package(folder, name, version, source):
    root = folder / f"root-{version}"
    (root / "usr/lib").mkdir(parents=True)
    (root / "src.c").write_text(source)
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", root / "usr/lib/libdemo.so.1", root / "src.c"], check=True)
    (root / "src.c").unlink()
    (root / ".PKGINFO").write_text(f"pkgname = {name}\npkgver = {version}\narch = x86_64\n")
    filename = f"{name}-{version}-x86_64.pkg.tar.zst"
    subprocess.run(["bsdtar", "--zstd", "-cf", folder / filename, "-C", root, ".PKGINFO", "usr"], check=True)
    return filename


def make_db(path, packages):
    with tarfile.open(path, "w:gz") as archive:
        for name, version, filename, digest in packages:
            text = (f"%FILENAME%\n{filename}\n\n%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%CSIZE%\n100\n\n"
                    f"%SHA256SUM%\n{digest}\n\n%PGPSIG%\n{base64.b64encode(b'sig').decode()}\n\n%ARCH%\nx86_64\n")
            data = text.encode()
            info = tarfile.TarInfo(f"{name}-{version}/desc")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


@needs_tools
def test_feed_records_an_update_and_its_gains(tmp_path, monkeypatch, capsys):
    mirror = tmp_path / "mirror" / "core" / "os" / "x86_64"
    mirror.mkdir(parents=True)
    archive = tmp_path / "archive" / "d" / "demo"
    archive.mkdir(parents=True)
    old = make_package(archive, "demo", "1.0-1", "int f(void){return 1;}\n")
    (archive / f"{old}.sig").write_bytes(b"sig")
    new = make_package(mirror, "demo", "1.1-1", "#include <stdlib.h>\nint f(void){return system(\"true\");}\n")
    digest = hashlib.sha256((mirror / new).read_bytes()).hexdigest()

    monkeypatch.setattr(archfeed, "ARCHIVE", (tmp_path / "archive").as_uri())
    monkeypatch.setattr(archfeed.Keyring, "__init__", lambda self, pubring=None: setattr(self, "home", str(tmp_path / "k")))
    monkeypatch.setattr(archfeed.Keyring, "verify", lambda self, path, signature: True)
    options = ["--repos", "core", "--mirror", (tmp_path / "mirror").as_uri() + "/$repo/os/$arch",
               "--log", str(tmp_path / "log.jsonl"), "--feed", str(tmp_path / "feed.jsonl"),
               "--state", str(tmp_path / "state.json")]

    make_db(mirror / "core.db", [("demo", "1.0-1", old, "0")])
    assert run_feed(["update", *options]) == 0
    assert "Started the feed" in capsys.readouterr().out

    make_db(mirror / "core.db", [("demo", "1.1-1", new, digest)])
    assert run_feed(["update", *options]) == 0
    entry = json.loads((tmp_path / "feed.jsonl").read_text().splitlines()[-1])

    assert (entry["package"], entry["from"], entry["to"], entry["status"]) == ("demo", "1.0-1", "1.1-1", "compared")
    assert [gain["detail"] for gain in entry["strong"]] == ["now uses shell: system"]
    assert json.loads((tmp_path / "state.json").read_text())["core"]["demo"] == "1.1-1"

    assert run_feed(["report", "--feed", str(tmp_path / "feed.jsonl")]) == 0
    assert "[STRONG]" in capsys.readouterr().out
    assert run_feed(["report", "--html", "--feed", str(tmp_path / "feed.jsonl"), "--log", str(tmp_path / "log.jsonl")]) == 0
    assert "now uses shell: system" in capsys.readouterr().out


@needs_tools
def test_a_tampered_archive_is_refused(tmp_path, monkeypatch):
    mirror = tmp_path / "mirror" / "core" / "os" / "x86_64"
    mirror.mkdir(parents=True)
    new = make_package(mirror, "demo", "2.0-1", "int f(void){return 2;}\n")
    monkeypatch.setattr(archfeed.Keyring, "__init__", lambda self, pubring=None: setattr(self, "home", str(tmp_path / "k")))
    monkeypatch.setattr(archfeed.Keyring, "verify", lambda self, path, signature: True)
    paths = {"log": tmp_path / "log.jsonl", "feed": tmp_path / "feed.jsonl", "state": tmp_path / "state.json"}
    (tmp_path / "state.json").write_text(json.dumps({"core": {"demo": None}}))
    make_db(mirror / "core.db", [("demo", "2.0-1", new, "0" * 64)])

    entries = archfeed.update(["core"], paths=paths, base_url=(tmp_path / "mirror").as_uri() + "/$repo/os/$arch")

    assert entries[0]["status"] == "the archive's signature or SHA-256 did not verify"
    assert not (tmp_path / "log.jsonl").exists() or (tmp_path / "log.jsonl").read_text() == ""


def test_timer_units_are_printed(capsys):
    assert run_feed(["timer"]) == 0
    text = capsys.readouterr().out
    assert "OnCalendar=hourly" in text and "feed update --quiet" in text
