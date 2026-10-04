import pytest

from xray.chain import chain_lines


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


@pytest.fixture
def installed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "pkgq" / "__init__.py")
    monkeypatch.syspath_prepend(str(site))

    return site


def test_python_launcher_expands_into_installed_code(tmp_path, installed):
    core = write(installed / "pkgq" / "core.py", "def main():\n    pass\n")
    tool = write(
        tmp_path / "tool", "#!/usr/bin/env python3\nfrom pkgq.core import main\n"
    )

    assert chain_lines(tool) == [
        f"{tool.resolve()} [python]",
        f"└── core.py -> {core.resolve()} [python]",
    ]


def test_relative_imports_are_followed(tmp_path, installed):
    core = write(installed / "pkgq" / "core.py", "from .util import x\n")
    util = write(installed / "pkgq" / "util.py")
    tool = write(
        tmp_path / "tool", "#!/usr/bin/env python3\nimport pkgq.core\n"
    )

    assert chain_lines(tool) == [
        f"{tool.resolve()} [python]",
        f"└── core.py -> {core.resolve()} [python]",
        f"    └── util.py -> {util.resolve()} [python]",
    ]


def test_package_init_is_named_with_its_folder(tmp_path, installed):
    init = installed / "pkgq" / "__init__.py"
    tool = write(tmp_path / "tool", "#!/usr/bin/env python3\nimport pkgq\n")

    assert chain_lines(tool) == [
        f"{tool.resolve()} [python]",
        f"└── pkgq/__init__.py -> {init.resolve()} [python]",
    ]
