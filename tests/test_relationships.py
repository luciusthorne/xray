import pytest

from xray.errors import AnalysisError, FileError
from xray.relationships import Relationship, find_relationships


UTILS = "def calculate():\n    return 1\n"


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def summary(relationships):
    return [
        (r.kind, r.source, r.name, r.line, r.status, r.target)
        for r in relationships
    ]


def test_class_inherits_local_class(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "class Base:\n"
        "    pass\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n",
    )

    assert find_relationships(main) == [
        Relationship(
            "inherits",
            "Child",
            "Base",
            4,
            str(main),
            "resolved",
            "main.py:Base",
        ),
    ]


def test_class_inherits_imported_class(tmp_path):
    write(tmp_path, "utils.py", "class Base:\n    pass\n")
    main = write(
        tmp_path,
        "main.py",
        "from utils import Base\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n",
    )

    assert summary(find_relationships(main)) == [
        ("inherits", "Child", "Base", 3, "resolved", "utils.py:Base"),
    ]


def test_external_base_class(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "from collections import OrderedDict\n"
        "\n"
        "class Child(OrderedDict):\n"
        "    pass\n",
    )

    assert summary(find_relationships(main)) == [
        ("inherits", "Child", "OrderedDict", 3, "external", None),
    ]


def test_unknown_base_is_ignored(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "class Child(object):\n"
        "    pass\n"
        "\n"
        "class Other(Unknown):\n"
        "    pass\n",
    )

    assert find_relationships(main) == []


def test_function_calls_local_function(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "def main():\n"
        "    helper()\n",
    )

    assert find_relationships(main) == [
        Relationship(
            "calls",
            "main",
            "helper",
            5,
            str(main),
            "resolved",
            "main.py:helper",
        ),
    ]


def test_function_calls_imported_function(tmp_path):
    write(tmp_path, "utils.py", UTILS)
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate\n"
        "\n"
        "def run():\n"
        "    calculate()\n",
    )

    assert summary(find_relationships(main)) == [
        (
            "calls",
            "run",
            "calculate",
            4,
            "resolved",
            "utils.py:calculate",
        ),
    ]


def test_unresolved_imported_call(tmp_path):
    write(tmp_path, "utils.py", "def other():\n    pass\n")
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate\n"
        "\n"
        "def run():\n"
        "    calculate()\n",
    )

    assert summary(find_relationships(main)) == [
        ("calls", "run", "calculate", 4, "unresolved", None),
    ]


def test_method_calls_self_method(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "class User:\n"
        "    def save(self):\n"
        "        self.validate()\n"
        "\n"
        "    def validate(self):\n"
        "        pass\n",
    )

    assert summary(find_relationships(main)) == [
        (
            "calls",
            "User.save",
            "self.validate",
            3,
            "resolved",
            "main.py:User.validate",
        ),
    ]


def test_self_call_to_unknown_method_is_ignored(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "class User:\n"
        "    def save(self):\n"
        "        self.missing()\n",
    )

    assert find_relationships(main) == []


def test_calls_to_unknown_names_are_ignored(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "def run():\n"
        "    print('x')\n"
        "    other()\n",
    )

    assert find_relationships(main) == []


def test_module_level_calls_are_not_recorded(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "helper()\n",
    )

    assert find_relationships(main) == []


def test_instantiation_counts_as_call(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "class User:\n"
        "    pass\n"
        "\n"
        "def make():\n"
        "    return User()\n",
    )

    assert summary(find_relationships(main)) == [
        ("calls", "make", "User", 5, "resolved", "main.py:User"),
    ]


def test_nested_function_calls_belong_to_outer(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "def outer():\n"
        "    def inner():\n"
        "        helper()\n",
    )

    assert summary(find_relationships(main)) == [
        ("calls", "outer", "helper", 6, "resolved", "main.py:helper"),
    ]


def test_async_function_calls(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "async def run():\n"
        "    helper()\n",
    )

    assert summary(find_relationships(main)) == [
        ("calls", "run", "helper", 5, "resolved", "main.py:helper"),
    ]


def test_results_follow_source_order(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "class Base:\n"
        "    pass\n"
        "\n"
        "class Child(Base):\n"
        "    def run(self):\n"
        "        helper()\n",
    )

    assert [
        (r.kind, r.line) for r in find_relationships(main)
    ] == [
        ("inherits", 7),
        ("calls", 9),
    ]


def test_missing_file_raises_file_error(tmp_path):
    with pytest.raises(FileError):
        find_relationships(tmp_path / "missing.py")


def test_invalid_syntax_raises_analysis_error(tmp_path):
    broken = write(tmp_path, "broken.py", "def broken(:\n")

    with pytest.raises(AnalysisError):
        find_relationships(broken)
