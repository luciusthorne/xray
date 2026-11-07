import shutil
import subprocess
from pathlib import Path

import pytest

import xray.provenance as provenance_module
from xray.provenance import package_of


def fake_run(returncode=0, stdout=""):
    def run(args, **kwargs):
        run.args = args

        return subprocess.CompletedProcess(args, returncode, stdout, "")

    return run


def test_returns_the_owning_package(tmp_path, monkeypatch):
    run = fake_run(0, "coreutils-9.10-5.fc44.x86_64\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)
    monkeypatch.setattr(provenance_module.shutil, "which", lambda name: "/usr/bin/rpm" if name == "rpm" else None)

    assert package_of(tmp_path) == "coreutils-9.10-5.fc44.x86_64"


def test_unowned_file_gives_none(tmp_path, monkeypatch):
    run = fake_run(1, "file /x is not owned by any package\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert package_of(tmp_path) is None


def test_missing_rpm_gives_none(tmp_path, monkeypatch):
    def run(args, **kwargs):
        raise FileNotFoundError("rpm")

    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert package_of(tmp_path) is None


def test_empty_output_gives_none(tmp_path, monkeypatch):
    run = fake_run(0, "\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert package_of(tmp_path) is None


def test_asks_rpm_about_the_resolved_path(tmp_path, monkeypatch):
    target = tmp_path / "real"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    run = fake_run(0, "pkg-1-1.noarch\n")
    monkeypatch.setattr(provenance_module.subprocess, "run", run)
    monkeypatch.setattr(
        provenance_module.shutil,
        "which",
        lambda name: "/usr/bin/rpm" if name == "rpm" else None,
    )

    package_of(link)

    assert run.args[0] == "rpm"
    assert run.args[-1] == str(target.resolve())


def _rpm_owns_ls():
    rpm, ls = shutil.which("rpm"), shutil.which("ls")
    if rpm is None or ls is None:
        return False
    # Debian/Ubuntu can install the rpm tool without an RPM database.
    probe = subprocess.run(
        [rpm, "-qf", str(Path(ls).resolve())],
        check=False,
        capture_output=True,
        text=True,
    )
    return probe.returncode == 0


@pytest.mark.skipif(not _rpm_owns_ls(), reason="ls is not owned by an RPM package")
def test_real_system_owner_of_ls():
    ls = shutil.which("ls")

    assert package_of(Path(ls)).startswith("coreutils-")


# -- dpkg (Debian, Ubuntu) ---------------------------------------------------

def _dpkg_system(monkeypatch, owners, versions, calls=None):
    """Pretend only dpkg exists; owners maps dpkg-recorded paths to packages."""

    monkeypatch.setattr(provenance_module.shutil, "which",
                        lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None)

    def run(args, **kwargs):
        if calls is not None:
            calls.append(args)
        if args[:2] == ["dpkg-query", "-S"]:
            lines = [f"{owners[p]}: {p}" for p in args[3:] if p in owners]
            lines.insert(0, "diversion by dash from: /bin/sh")
            return subprocess.CompletedProcess(args, 0 if lines else 1, "\n".join(lines) + "\n", "")
        if args[:2] == ["dpkg-query", "-W"]:
            out = "".join(f"{p} {p.split(':')[0]} {versions[p.split(':')[0]]}\n" for p in args[4:] if p.split(':')[0] in versions)
            return subprocess.CompletedProcess(args, 0, out, "")
        raise FileNotFoundError(args[0])

    monkeypatch.setattr(provenance_module.subprocess, "run", run)


def test_dpkg_owner_through_merged_usr(monkeypatch):
    # dpkg recorded /bin/ls; the file is reached as /usr/bin/ls.
    _dpkg_system(monkeypatch, {"/bin/ls": "coreutils"}, {"coreutils": "9.4-3.1"})

    assert provenance_module._dpkg_package("/usr/bin/ls") == "coreutils 9.4-3.1"


def test_dpkg_batch_lookup_in_two_calls(monkeypatch):
    calls = []
    _dpkg_system(monkeypatch, {"/usr/bin/curl": "curl", "/usr/lib/x86_64-linux-gnu/libz.so.1": "zlib1g:amd64"},
                 {"curl": "8.5.0-2", "zlib1g": "1:1.3.dfsg-3"}, calls)

    owned = provenance_module.packages_of(["/usr/bin/curl", "/usr/lib/x86_64-linux-gnu/libz.so.1", "/tmp/x"])
    assert owned == {
        "/usr/bin/curl": ("dpkg", "curl 8.5.0-2"),
        "/usr/lib/x86_64-linux-gnu/libz.so.1": ("dpkg", "zlib1g 1:1.3.dfsg-3"),
    }
    assert len(calls) == 2  # one -S for every path, one -W for every package


def test_dpkg_package_url(monkeypatch):
    from xray import sbom

    monkeypatch.setattr(sbom, "_os_id", lambda: "ubuntu")
    assert sbom._purl("curl 8.5.0-2", "dpkg") == "pkg:deb/ubuntu/curl@8.5.0-2"
