import pytest

from xray.errors import AnalysisError, FileError
from xray.references import Reference, find_references


UTILS = "def calculate():\n    return 1\n"


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def test_call_resolves_to_definition(tmp_path):
    write(tmp_path, "utils.py", UTILS)
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate\n\ncalculate()\n",
    )

    assert find_references(main) == [
        Reference(
            "calculate",
            3,
            str(main),
            "resolved",
            "utils.py:calculate",
        ),
    ]


def test_alias_resolves_to_original(tmp_path):
    write(tmp_path, "utils.py", UTILS)
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate as calc\n\ncalc()\n",
    )

    assert find_references(main) == [
        Reference(
            "calc",
            3,
            str(main),
            "resolved",
            "utils.py:calculate",
        ),
    ]


def test_non_call_use_is_a_reference(tmp_path):
    write(tmp_path, "utils.py", UTILS)
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate\n\nvalues = [calculate]\n",
    )

    refs = find_references(main)

    assert [(r.name, r.line, r.status) for r in refs] == [
        ("calculate", 3, "resolved"),
    ]


def test_class_reference(tmp_path):
    write(tmp_path, "utils.py", "class User:\n    pass\n")
    main = write(
        tmp_path,
        "main.py",
        "from utils import User\n\nUser()\n",
    )

    refs = find_references(main)

    assert [(r.status, r.target) for r in refs] == [
        ("resolved", "utils.py:User"),
    ]


def test_references_follow_source_order(tmp_path):
    write(tmp_path, "utils.py", UTILS)
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate\n\ncalculate()\ncalculate()\n",
    )

    refs = find_references(main)

    assert [r.line for r in refs] == [3, 4]


def test_package_module_resolves(tmp_path):
    write(tmp_path, "pkg/__init__.py", "")
    write(tmp_path, "pkg/helpers.py", "def run():\n    pass\n")
    main = write(
        tmp_path,
        "main.py",
        "from pkg.helpers import run\n\nrun()\n",
    )

    refs = find_references(main, tmp_path)

    assert [(r.status, r.target) for r in refs] == [
        ("resolved", "pkg/helpers.py:run"),
    ]


def test_relative_import_resolves(tmp_path):
    write(tmp_path, "pkg/helpers.py", "def run():\n    pass\n")
    main = write(
        tmp_path,
        "pkg/main.py",
        "from .helpers import run\n\nrun()\n",
    )

    assert find_references(main, tmp_path) == [
        Reference(
            "run",
            3,
            str(main),
            "resolved",
            "pkg/helpers.py:run",
        ),
    ]


def test_missing_symbol_is_unresolved(tmp_path):
    write(tmp_path, "utils.py", "def other():\n    pass\n")
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate\n\ncalculate()\n",
    )

    refs = find_references(main)

    assert [(r.status, r.target) for r in refs] == [
        ("unresolved", None),
    ]


def test_external_import_is_marked_external(tmp_path):
    main = write(
        tmp_path,
        "main.py",
        "from os import path\n\npath\n",
    )

    refs = find_references(main)

    assert [(r.name, r.status, r.target) for r in refs] == [
        ("path", "external", None),
    ]


def test_star_import_creates_no_references(tmp_path):
    write(tmp_path, "utils.py", UTILS)
    main = write(
        tmp_path,
        "main.py",
        "from utils import *\n\ncalculate()\n",
    )

    assert find_references(main) == []


def test_module_attribute_calls_are_not_resolved_yet(tmp_path):
    write(tmp_path, "utils.py", UTILS)
    main = write(
        tmp_path,
        "main.py",
        "import utils\n\nutils.calculate()\n",
    )

    assert find_references(main) == []


def test_unimported_names_are_ignored(tmp_path):
    main = write(tmp_path, "main.py", "calculate()\n")

    assert find_references(main) == []


def test_broken_target_module_is_unresolved(tmp_path):
    write(tmp_path, "utils.py", "def broken(:\n")
    main = write(
        tmp_path,
        "main.py",
        "from utils import calculate\n\ncalculate()\n",
    )

    refs = find_references(main)

    assert [r.status for r in refs] == ["unresolved"]


def test_missing_file_raises_file_error(tmp_path):
    with pytest.raises(FileError):
        find_references(tmp_path / "missing.py")


def test_invalid_syntax_raises_analysis_error(tmp_path):
    broken = write(tmp_path, "broken.py", "def broken(:\n")

    with pytest.raises(AnalysisError):
        find_references(broken)
