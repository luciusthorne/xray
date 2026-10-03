import pytest

from xray.errors import AnalysisError, FileError
from xray.unused import (
    UnusedImport,
    find_unused_imports,
    find_unused_imports_in_source,
)


def check(source):
    return find_unused_imports_in_source(source, "example.py")


def summary(items):
    return [(i.name, i.module, i.line) for i in items]


def test_unused_plain_import():
    assert check("import json\n") == [
        UnusedImport("json", "json", 1, "example.py"),
    ]


def test_used_import_is_not_reported():
    assert check("import json\njson.dumps({})\n") == []


def test_unused_from_import():
    assert summary(check("from utils import calculate\n")) == [
        ("calculate", "utils", 1),
    ]


def test_unused_alias_binds_the_alias():
    assert summary(check("import numpy as np\n")) == [
        ("np", "numpy", 1),
    ]


def test_used_alias_is_not_reported():
    assert check("import numpy as np\nnp.array([])\n") == []


def test_from_alias_binds_the_alias():
    assert summary(check("from os import path as p\n")) == [
        ("p", "os", 1),
    ]


def test_dotted_import_binds_first_name():
    assert check("import os.path\nos.getcwd()\n") == []


def test_dotted_import_unused_reports_binding():
    assert summary(check("import os.path\n")) == [
        ("os", "os.path", 1),
    ]


def test_multiple_imports_on_one_line():
    source = "import os, sys\nos.getcwd()\n"

    assert summary(check(source)) == [("sys", "sys", 1)]


def test_use_inside_nested_function_counts():
    source = (
        "import json\n"
        "\n"
        "def f():\n"
        "    return json.dumps(1)\n"
    )

    assert check(source) == []


def test_use_as_base_class_counts():
    source = (
        "from abc import ABC\n"
        "\n"
        "class A(ABC):\n"
        "    pass\n"
    )

    assert check(source) == []


def test_star_import_is_ignored():
    assert check("from os import *\n") == []


def test_future_import_is_ignored():
    assert check("from __future__ import annotations\n") == []


def test_all_counts_as_use():
    source = (
        "from utils import calculate\n"
        "\n"
        "__all__ = ['calculate']\n"
    )

    assert check(source) == []


def test_augmented_all_counts_as_use():
    source = (
        "from utils import first\n"
        "\n"
        "__all__ = []\n"
        "__all__ += ['first']\n"
    )

    assert check(source) == []


def test_string_annotation_counts():
    source = (
        "from typing import List\n"
        "\n"
        "def f(x: 'List[int]') -> None:\n"
        "    pass\n"
    )

    assert check(source) == []


def test_nested_string_annotation_counts():
    source = (
        "from typing import Optional\n"
        "from models import Foo\n"
        "\n"
        "def f(x: Optional['Foo']) -> None:\n"
        "    pass\n"
    )

    assert check(source) == []


def test_return_string_annotation_counts():
    source = (
        "from models import Foo\n"
        "\n"
        "def f() -> 'Foo':\n"
        "    pass\n"
    )

    assert check(source) == []


def test_import_inside_function_is_reported():
    source = "def f():\n    import json\n"

    assert summary(check(source)) == [("json", "json", 2)]


def test_results_follow_source_order():
    source = "import b\nimport a\nfrom c import d\n"

    assert summary(check(source)) == [
        ("b", "b", 1),
        ("a", "a", 2),
        ("d", "c", 3),
    ]


def test_reassigned_name_does_not_count_as_use():
    assert summary(check("import json\njson = 1\n")) == [
        ("json", "json", 1),
    ]


def test_init_file_is_skipped():
    result = find_unused_imports_in_source(
        "import json\n",
        "pkg/__init__.py",
    )

    assert result == []


def test_relative_import_module_keeps_dots():
    source = "from . import helpers\nfrom .utils import run\n"

    assert summary(check(source)) == [
        ("helpers", ".", 1),
        ("run", ".utils", 2),
    ]


def test_empty_source():
    assert check("") == []


def test_find_unused_imports_from_file(tmp_path):
    target = tmp_path / "example.py"
    target.write_text("import json\n", encoding="utf-8")

    assert find_unused_imports(target) == [
        UnusedImport("json", "json", 1, str(target)),
    ]


def test_missing_file_raises_file_error(tmp_path):
    with pytest.raises(FileError):
        find_unused_imports(tmp_path / "missing.py")


def test_invalid_syntax_raises_analysis_error(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")

    with pytest.raises(AnalysisError):
        find_unused_imports(broken)
