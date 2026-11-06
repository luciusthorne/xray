import shutil
import subprocess
import tarfile

import pytest

from xray import rootfs
from xray.driftverbs import run_build


def _bwrap_works():
    if shutil.which("bwrap") is None:
        return False
    done = subprocess.run(["bwrap", "--dev-bind", "/", "/", "--unshare-all", "true"], capture_output=True, check=False)
    return done.returncode == 0


needs_bwrap = pytest.mark.skipif(not _bwrap_works(), reason="needs working unprivileged bubblewrap")


def test_symlink_chain_follows_links_in_the_path(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "tool").write_text("x")
    (tmp_path / "link").symlink_to("real")
    (tmp_path / "real" / "alias").symlink_to("tool")

    chain = rootfs._symlink_chain(str(tmp_path / "link" / "alias"))

    assert (str(tmp_path / "link"), "real") in chain
    assert (str(tmp_path / "real" / "alias"), "tool") in chain


def test_needed_files_include_libraries_loader_and_their_links():
    files, entries = rootfs.needed_files(["ls"])

    assert any("ld-linux" in path for path in files)
    assert any(path.endswith("/libc.so.6") for path in files + entries)


@needs_bwrap
def test_built_root_runs_the_commands_and_nothing_else(tmp_path, capsys):
    root = tmp_path / "root"

    assert run_build(["--commands", "ls", "-o", str(root), "--check", "ls /"]) == 0
    assert "check `ls /`: ok" in capsys.readouterr().out
    assert rootfs.check(root, "cat /etc/hostname").returncode != 0  # cat was not asked for


@needs_bwrap
def test_tar_output(tmp_path, capsys):
    output = tmp_path / "root.tar"

    assert run_build(["--commands", "ls", "-o", str(output)]) == 0
    with tarfile.open(output) as archive:
        names = archive.getnames()
    assert any(name.endswith("bin/ls") for name in names) and "tmp" in names
