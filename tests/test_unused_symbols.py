from xray.symbols import Symbol
from xray.unused_symbols import find_unused_symbols


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def summary(symbols):
    return [(s.qualified_name, s.kind, s.file, s.line) for s in symbols]


def test_unused_function(tmp_path):
    write(tmp_path, "lib.py", "def calculate():\n    pass\n")

    assert find_unused_symbols(tmp_path) == [
        Symbol("calculate", "function", "lib.py", 1),
    ]


def test_function_used_from_another_file(tmp_path):
    write(tmp_path, "lib.py", "def calculate():\n    pass\n")
    write(
        tmp_path,
        "app.py",
        "from lib import calculate\ncalculate()\n",
    )

    assert find_unused_symbols(tmp_path) == []


def test_function_used_in_same_file(tmp_path):
    write(
        tmp_path,
        "lib.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "def run():\n"
        "    helper()\n",
    )

    assert summary(find_unused_symbols(tmp_path)) == [
        ("run", "function", "lib.py", 4),
    ]


def test_unused_class(tmp_path):
    write(tmp_path, "lib.py", "class LegacyParser:\n    pass\n")

    assert find_unused_symbols(tmp_path) == [
        Symbol("LegacyParser", "class", "lib.py", 1),
    ]


def test_class_used_as_base_class(tmp_path):
    write(tmp_path, "lib.py", "class Base:\n    pass\n")
    write(
        tmp_path,
        "app.py",
        "from lib import Base\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n",
    )

    assert summary(find_unused_symbols(tmp_path)) == [
        ("Child", "class", "app.py", 3),
    ]


def test_unused_method(tmp_path):
    write(
        tmp_path,
        "lib.py",
        "class User:\n"
        "    def save(self):\n"
        "        pass\n"
        "\n"
        "    def delete(self):\n"
        "        pass\n",
    )
    write(
        tmp_path,
        "app.py",
        "from lib import User\nUser().save()\n",
    )

    assert find_unused_symbols(tmp_path) == [
        Symbol("delete", "method", "lib.py", 5, "User"),
    ]


def test_method_used_through_self(tmp_path):
    write(
        tmp_path,
        "lib.py",
        "class User:\n"
        "    def save(self):\n"
        "        self.validate()\n"
        "\n"
        "    def validate(self):\n"
        "        pass\n",
    )
    write(tmp_path, "app.py", "from lib import User\nUser()\n")

    assert summary(find_unused_symbols(tmp_path)) == [
        ("User.save", "method", "lib.py", 2),
    ]


def test_dunder_methods_are_ignored(tmp_path):
    write(
        tmp_path,
        "lib.py",
        "class User:\n"
        "    def __init__(self):\n"
        "        pass\n"
        "\n"
        "    def __str__(self):\n"
        "        return 'user'\n",
    )
    write(tmp_path, "app.py", "from lib import User\nUser()\n")

    assert find_unused_symbols(tmp_path) == []


def test_decorated_definitions_are_ignored(tmp_path):
    write(
        tmp_path,
        "lib.py",
        "import functools\n"
        "\n"
        "@functools.cache\n"
        "def cached():\n"
        "    pass\n",
    )

    assert find_unused_symbols(tmp_path) == []


def test_methods_of_subclasses_are_ignored(tmp_path):
    write(
        tmp_path,
        "lib.py",
        "from threading import Thread\n"
        "\n"
        "class Worker(Thread):\n"
        "    def run(self):\n"
        "        pass\n",
    )
    write(tmp_path, "app.py", "from lib import Worker\nWorker()\n")

    assert find_unused_symbols(tmp_path) == []


def test_main_function_is_ignored(tmp_path):
    write(tmp_path, "lib.py", "def main():\n    pass\n")

    assert find_unused_symbols(tmp_path) == []


def test_test_files_and_conftest_are_ignored(tmp_path):
    write(tmp_path, "tests/test_lib.py", "def test_x():\n    pass\n")
    write(tmp_path, "conftest.py", "def fixture_x():\n    pass\n")

    assert find_unused_symbols(tmp_path) == []


def test_use_only_in_tests_counts(tmp_path):
    write(tmp_path, "lib.py", "def calculate():\n    pass\n")
    write(
        tmp_path,
        "tests/test_lib.py",
        "from lib import calculate\n"
        "\n"
        "def test_it():\n"
        "    calculate()\n",
    )

    assert find_unused_symbols(tmp_path) == []


def test_init_reexport_counts_as_use(tmp_path):
    write(tmp_path, "pkg/__init__.py", "from .core import run\n")
    write(tmp_path, "pkg/core.py", "def run():\n    pass\n")

    assert find_unused_symbols(tmp_path) == []


def test_all_counts_as_use(tmp_path):
    write(
        tmp_path,
        "lib.py",
        "def public():\n"
        "    pass\n"
        "\n"
        "__all__ = ['public']\n",
    )

    assert find_unused_symbols(tmp_path) == []


def test_exact_string_counts_as_use(tmp_path):
    write(tmp_path, "lib.py", "def plugin():\n    pass\n")
    write(
        tmp_path,
        "app.py",
        "import lib\n\nhandler = getattr(lib, 'plugin')\n",
    )

    assert find_unused_symbols(tmp_path) == []


def test_string_annotation_counts_as_use(tmp_path):
    write(tmp_path, "lib.py", "class Foo:\n    pass\n")
    write(
        tmp_path,
        "app.py",
        "from lib import Foo\n"
        "\n"
        "def f(x: 'Foo') -> None:\n"
        "    pass\n",
    )

    assert summary(find_unused_symbols(tmp_path)) == [
        ("f", "function", "app.py", 3),
    ]


def test_module_attribute_use_counts(tmp_path):
    write(tmp_path, "lib.py", "def calculate():\n    pass\n")
    write(tmp_path, "app.py", "import lib\nlib.calculate()\n")

    assert find_unused_symbols(tmp_path) == []


def test_recursive_function_counts_as_used(tmp_path):
    write(tmp_path, "lib.py", "def loop():\n    loop()\n")

    assert find_unused_symbols(tmp_path) == []


def test_variables_are_not_reported(tmp_path):
    write(tmp_path, "lib.py", "VERSION = 1\n")

    assert find_unused_symbols(tmp_path) == []


def test_package_paths_are_relative(tmp_path):
    write(tmp_path, "pkg/util.py", "def helper():\n    pass\n")

    assert find_unused_symbols(tmp_path) == [
        Symbol("helper", "function", "pkg/util.py", 1),
    ]


def test_results_are_sorted_by_file_then_line(tmp_path):
    write(
        tmp_path,
        "b.py",
        "def second():\n    pass\n\ndef first():\n    pass\n",
    )
    write(tmp_path, "a.py", "def only():\n    pass\n")

    assert summary(find_unused_symbols(tmp_path)) == [
        ("only", "function", "a.py", 1),
        ("second", "function", "b.py", 1),
        ("first", "function", "b.py", 4),
    ]


def test_broken_files_are_skipped(tmp_path):
    write(tmp_path, "broken.py", "def broken(:\n")
    write(tmp_path, "lib.py", "def helper():\n    pass\n")

    assert summary(find_unused_symbols(tmp_path)) == [
        ("helper", "function", "lib.py", 1),
    ]


def test_pycache_is_ignored(tmp_path):
    write(
        tmp_path,
        "__pycache__/cached.py",
        "def helper():\n    pass\n",
    )

    assert find_unused_symbols(tmp_path) == []


def test_empty_project(tmp_path):
    assert find_unused_symbols(tmp_path) == []
