import json

from xray.crossbuild import by_name, compare_builds
from xray.driftverbs import run_compare


def elf(**fields):
    base = {"kind": "elf", "sha256": "a", "needed": ["libc.so.6"], "classes": {}, "ifuncs": 0, "constructors": 0}
    base.update(fields)
    return base


def test_files_are_paired_by_name_across_layouts():
    left = {"usr/lib/liblzma.so.5.6.1": elf(), "usr/bin/xz": elf()}
    right = {"liblzma5.deb:usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1": elf(sha256="b")}

    report = compare_builds(left, right)

    assert report["shared"] == 1
    assert report["only_in_left"] == ["xz"]
    assert report["differences"] == []
    assert set(by_name(right)) == {"liblzma.so.5.6.1"}


def test_the_real_xz_difference_is_strong_without_the_loader_hook_rule():
    """Debian's backdoored 5.6.1 vs Arch's 5.6.1: same release, only one links the loader."""

    arch = {"usr/lib/liblzma.so.5.6.1": elf(soname="liblzma.so.5", ifuncs=2)}
    debian = {"usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1": elf(sha256="b", soname="liblzma.so.5", ifuncs=2,
                                                               needed=["libc.so.6", "ld-linux-x86-64.so.2"])}

    report = compare_builds(arch, debian)
    item = report["differences"][0]

    assert report["strong"] == ["liblzma.so.5.6.1"]
    assert [change["field"] for change in item["only_right"]] == ["loader-hook", "needed"]
    assert item["only_left"] == []

    # Without IFUNCs the loader-hook rule cannot fire; depending on the loader is still a strong difference.
    plain = compare_builds({"a/libx.so.1": elf()}, {"b/libx.so.1": elf(sha256="b", needed=["libc.so.6", "ld-linux-x86-64.so.2"])})
    assert plain["strong"] == ["libx.so.1"]


def test_configure_differences_are_weak_and_capability_classes_strong():
    left = {"bin/tool": elf(), "lib/libz.so.1": elf()}
    right = {"bin/tool": elf(sha256="b", needed=["libc.so.6", "libsystemd.so.0"]),
             "lib/libz.so.1": elf(sha256="c", classes={"exec": ["execve"]})}

    report = compare_builds(left, right)

    assert report["strong"] == ["libz.so.1"]
    assert {item["name"]: item["strong"] for item in report["differences"]} == {"tool": False, "libz.so.1": True}


def test_cli_compares_directories(tmp_path, capsys):
    for side, body in (("a", "#!/bin/sh\nls\n"), ("b", "#!/bin/sh\nls\ncurl -s x\n")):
        tool = tmp_path / side / "usr" / "bin" / "tool"
        tool.parent.mkdir(parents=True)
        tool.write_text(body)
        tool.chmod(0o755)

    assert run_compare([str(tmp_path / "a"), str(tmp_path / "b"), "--json", "--fail-on-strong"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["strong"] == ["tool"]
    assert any("net" in change["field"] for change in report["differences"][0]["only_right"])
