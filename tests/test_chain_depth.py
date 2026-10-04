import pytest

from xray.chain import chain_lines


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


@pytest.fixture
def installed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "pkgd" / "__init__.py")
    monkeypatch.syspath_prepend(str(site))

    return site


def make_tool(tmp_path):
    return write(tmp_path / "tool", "#!/usr/bin/env python3\nimport pkgd.a\n")


def test_depth_limit_is_reported(tmp_path, installed):
    a = write(installed / "pkgd" / "a.py", "from .b import x\n")
    b = write(installed / "pkgd" / "b.py", "from .c import x\n")
    c = write(installed / "pkgd" / "c.py", "from .d import x\n")
    write(installed / "pkgd" / "d.py")
    tool = make_tool(tmp_path)

    assert chain_lines(tool) == [
        f"{tool.resolve()} [python]",
        f"└── a.py -> {a.resolve()} [python]",
        f"    └── b.py -> {b.resolve()} [python]",
        f"        └── c.py -> {c.resolve()} [python]",
        "Truncated: depth limit (3) reached",
    ]


def test_no_notice_when_the_chain_ends_at_the_limit(tmp_path, installed):
    write(installed / "pkgd" / "a.py", "from .b import x\n")
    write(installed / "pkgd" / "b.py", "from .c import x\n")
    write(installed / "pkgd" / "c.py")
    tool = make_tool(tmp_path)

    lines = chain_lines(tool)

    assert len(lines) == 4
    assert not any(line.startswith("Truncated") for line in lines)


def test_notice_shows_the_chosen_limit(tmp_path, installed):
    a = write(installed / "pkgd" / "a.py", "from .b import x\n")
    write(installed / "pkgd" / "b.py")
    tool = make_tool(tmp_path)

    assert chain_lines(tool, max_depth=1) == [
        f"{tool.resolve()} [python]",
        f"└── a.py -> {a.resolve()} [python]",
        "Truncated: depth limit (1) reached",
    ]
