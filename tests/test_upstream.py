"""Upstream source for binaries without debug information (Arch .SRCINFO archives)."""

import hashlib
import io
import tarfile

from xray import upstream

SRCINFO = """pkgbase = hyprland
	pkgver = 0.56.2
	source = Hyprland-0.56.2.tar.gz::https://github.com/hyprwm/Hyprland/releases/download/v0.56.2/source-v0.56.2.tar.gz
	source = fix-build.patch
	source = git+https://github.com/hyprwm/hyprlang.git#tag=v0.6.0
	sha256sums = {digest}
	sha256sums = 1111
	sha256sums = SKIP
"""

CPP = """#include "HyprCtl.hpp"
namespace Debug {
std::string CHyprCtl::getReply(std::string request) {
    auto x = helper(request);   // a call, not a definition
    return x;
}
}
std::string helper(std::string r);
static std::string
helper(std::string r)
{
    return r;
}
"""

HPP = """class CHyprCtl {
  public:
    std::string getReply(std::string request);
};
"""


def _tarball(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_srcinfo_sources_and_git_archives(monkeypatch):
    monkeypatch.setattr(upstream, "pacman_package", lambda path: ("hyprland", "0.56.2-4", "hyprland"))
    urls = []

    def fetch_text(url):
        urls.append(url)
        return SRCINFO.format(digest="abc")

    info = upstream.find_upstream("/usr/bin/Hyprland", fetch_text=fetch_text)
    assert urls == ["https://gitlab.archlinux.org/archlinux/packaging/packages/hyprland/-/raw/0.56.2-4/.SRCINFO"]
    assert info.archives == [
        ("Hyprland-0.56.2.tar.gz", "https://github.com/hyprwm/Hyprland/releases/download/v0.56.2/source-v0.56.2.tar.gz", "abc"),
        ("hyprlang-v0.6.0.tar.gz", "https://github.com/hyprwm/hyprlang/archive/v0.6.0.tar.gz", None),
    ]
    assert info.patches == ["fix-build.patch"]


def test_prepare_checks_the_checksum_and_extracts_safely(tmp_path, monkeypatch):
    monkeypatch.setenv("XRAY_CACHE_DIR", str(tmp_path))
    data = _tarball({"src/debug/HyprCtl.cpp": CPP.encode(), "src/debug/HyprCtl.hpp": HPP.encode(),
                     "../escape.cpp": b"int x;", "bin/blob.so": b"\x7fELF"})
    good = upstream.Upstream("hyprland", "0.56.2-4", "hyprland",
                             archives=[("H.tar.gz", "https://x/H.tar.gz", hashlib.sha256(data).hexdigest())])
    upstream.prepare(good, fetch=lambda url: data)
    assert good.problem is None and good.verified
    assert (good.root / "src/debug/HyprCtl.cpp").is_file()
    assert not (good.root / "bin/blob.so").exists()          # only source text is extracted
    assert not (tmp_path / "upstream" / "escape.cpp").exists()  # no ../ escapes

    bad = upstream.Upstream("other", "1-1", "other", archives=[("O.tar.gz", "https://x/O.tar.gz", "0" * 64)])
    upstream.prepare(bad, fetch=lambda url: data)
    assert "checksum" in bad.problem and bad.root is None


def test_find_definition_in_cpp_and_c(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "HyprCtl.cpp").write_text(CPP)
    (tmp_path / "src" / "HyprCtl.hpp").write_text(HPP)

    file, start, lines = upstream.find_definition(tmp_path, "Debug::CHyprCtl::getReply")
    assert file.name == "HyprCtl.cpp" and start == 3            # inside a namespace, not the header prototype
    assert lines[0].startswith("std::string CHyprCtl::getReply") and lines[-1] == "}"

    file, start, lines = upstream.find_definition(tmp_path, "helper(std::string)")
    assert start == 9 and lines[:2] == ["static std::string", "helper(std::string r)"]  # not the call or prototype
    assert upstream.find_definition(tmp_path, "nowhere") is None


def test_note_says_how_far_to_trust_it():
    info = upstream.Upstream("hyprland", "0.56.2-4", "hyprland", archives=[("H.tar.gz", "u", "d")],
                             patches=["a.patch"], verified=True)
    text = upstream.note(info)
    assert "checksum verified" in text and "1 patch(es)" in text and "a guess" in text
