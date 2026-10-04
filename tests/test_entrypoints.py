import pytest

from xray.entrypoints import (
    CommandImport,
    command_kind,
    find_module_file,
    python_imports,
    resolve_launcher,
)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")

    return path


# ----------------------------------------------------------------------
# command_kind
# ----------------------------------------------------------------------


def test_elf_by_magic_bytes(tmp_path):
    path = write(tmp_path / "tool", b"\x7fELF" + bytes(60))

    assert command_kind(path) == "elf"


@pytest.mark.parametrize(
    "shebang, expected",
    [
        ("#!/usr/bin/python3", "python"),
        ("#!/usr/bin/env python3", "python"),
        ("#!/usr/bin/env -S python3 -u", "python"),
        ("#!/bin/sh", "shell"),
        ("#!/usr/bin/bash", "shell"),
        ("#!/usr/bin/env bash", "shell"),
        ("#!/usr/bin/perl -w", "perl"),
        ("#!/usr/bin/gjs", "script"),
    ],
)
def test_script_kinds_by_shebang(tmp_path, shebang, expected):
    path = write(tmp_path / "tool", shebang + "\necho hi\n")

    assert command_kind(path) == expected


def test_python_suffix_without_shebang(tmp_path):
    path = write(tmp_path / "tool.py", "print('hi')\n")

    assert command_kind(path) == "python"


def test_extension_does_not_override_shebang(tmp_path):
    path = write(tmp_path / "tool.txt", "#!/bin/sh\necho hi\n")

    assert command_kind(path) == "shell"


def test_plain_text_is_unknown(tmp_path):
    path = write(tmp_path / "notes", "just text\n")

    assert command_kind(path) == "unknown"


def test_missing_file_is_unknown(tmp_path):
    assert command_kind(tmp_path / "nope") == "unknown"


# ----------------------------------------------------------------------
# python_imports
# ----------------------------------------------------------------------


def test_python_imports_collects_absolute_modules(tmp_path):
    path = write(
        tmp_path / "tool",
        "#!/usr/bin/env python3\n"
        "import os.path\n"
        "import json, sys\n"
        "from _pytest.config import main\n"
        "from . import sibling\n"
        "from .sibling import thing\n",
    )

    assert python_imports(path) == (
        "_pytest.config",
        "json",
        "os.path",
        "sys",
    )


def test_python_imports_of_broken_file_is_empty(tmp_path):
    path = write(tmp_path / "tool", "def (:\n")

    assert python_imports(path) == ()


def test_python_imports_of_missing_file_is_empty(tmp_path):
    assert python_imports(tmp_path / "nope") == ()


# ----------------------------------------------------------------------
# find_module_file
# ----------------------------------------------------------------------


@pytest.fixture
def installed(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "pkgx" / "__init__.py", "")
    write(site / "pkgx" / "core.py", "def main():\n    pass\n")
    write(site / "pkgx" / "sub" / "__init__.py", "")
    write(site / "pkgx" / "sub" / "mod.py", "")
    monkeypatch.syspath_prepend(str(site))

    return site


def test_find_top_level_package(installed):
    assert find_module_file("pkgx") == installed / "pkgx" / "__init__.py"


def test_find_submodule_file(installed):
    assert find_module_file("pkgx.core") == installed / "pkgx" / "core.py"
    assert (
        find_module_file("pkgx.sub.mod")
        == installed / "pkgx" / "sub" / "mod.py"
    )


def test_find_subpackage_init(installed):
    assert (
        find_module_file("pkgx.sub")
        == installed / "pkgx" / "sub" / "__init__.py"
    )


def test_find_does_not_import_the_package(tmp_path, monkeypatch):
    site = tmp_path / "site"
    write(site / "boom" / "__init__.py", "raise RuntimeError('imported')\n")
    write(site / "boom" / "inner.py", "")
    monkeypatch.syspath_prepend(str(site))

    assert find_module_file("boom.inner") == site / "boom" / "inner.py"


def test_find_missing_module_is_none():
    assert find_module_file("definitely_not_installed_xyz") is None


def test_find_builtin_module_is_none():
    assert find_module_file("sys") is None


def test_find_stdlib_module():
    path = find_module_file("json")

    assert path is not None
    assert path.name == "__init__.py"


# ----------------------------------------------------------------------
# resolve_launcher
# ----------------------------------------------------------------------


def test_resolve_launcher_follows_into_installed_package(
    tmp_path, installed
):
    launcher = write(
        tmp_path / "bin" / "toolx",
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "from pkgx.core import main\n"
        "import not_installed_xyz\n"
        "sys.exit(main())\n",
    )

    result = resolve_launcher(launcher)

    assert [(i.module, i.kind) for i in result] == [
        ("not_installed_xyz", "missing"),
        ("pkgx.core", "found"),
        ("sys", "stdlib"),
    ]

    by_name = {i.module: i for i in result}

    assert by_name["pkgx.core"].origin == installed / "pkgx" / "core.py"
    assert by_name["not_installed_xyz"].origin is None
    assert by_name["sys"].origin is None


def test_resolve_launcher_of_non_python_is_empty(tmp_path):
    path = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    assert resolve_launcher(path) == ()


def test_command_import_is_a_value():
    assert CommandImport("a", "missing", None) == CommandImport(
        "a", "missing", None
    )
