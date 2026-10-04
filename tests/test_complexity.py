import pytest

from xray.complexity import (
    FunctionMetrics,
    analyze_complexity,
    analyze_complexity_source,
    analyze_project_complexity,
)
from xray.errors import AnalysisError, FileError


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def only(source):
    metrics = analyze_complexity_source(source, "example.py")

    assert len(metrics.functions) == 1

    return metrics.functions[0]


# ----------------------------------------------------------------------
# Cyclomatic complexity
# ----------------------------------------------------------------------


def test_simple_function_has_complexity_one():
    assert only("def f():\n    return 1\n").complexity == 1


def test_if_adds_one():
    source = (
        "def f(x):\n"
        "    if x:\n"
        "        return 1\n"
        "    return 0\n"
    )

    assert only(source).complexity == 2


def test_elif_and_else():
    source = (
        "def f(x):\n"
        "    if x == 1:\n"
        "        return 1\n"
        "    elif x == 2:\n"
        "        return 2\n"
        "    else:\n"
        "        return 3\n"
    )

    assert only(source).complexity == 3


def test_for_and_while_add_one_each():
    source = (
        "def f(items):\n"
        "    for item in items:\n"
        "        pass\n"
        "    while items:\n"
        "        pass\n"
    )

    assert only(source).complexity == 3


def test_async_for_adds_one():
    source = (
        "async def f(items):\n"
        "    async for item in items:\n"
        "        pass\n"
    )

    assert only(source).complexity == 2


def test_except_handlers_add_one_each():
    source = (
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError:\n"
        "        pass\n"
        "    except KeyError:\n"
        "        pass\n"
    )

    assert only(source).complexity == 3


def test_boolean_operands_add_one_each():
    source = "def f(a, b, c):\n    return a and b and c\n"

    assert only(source).complexity == 3


def test_mixed_boolean_operators():
    source = "def f(a, b, c):\n    return a and b or c\n"

    assert only(source).complexity == 3


def test_conditional_expression_adds_one():
    source = "def f(a):\n    return 1 if a else 2\n"

    assert only(source).complexity == 2


def test_comprehension_with_condition():
    source = "def f(items):\n    return [x for x in items if x]\n"

    assert only(source).complexity == 3


def test_comprehension_with_two_generators():
    source = "def f(rows):\n    return [x for row in rows for x in row]\n"

    assert only(source).complexity == 3


def test_nested_function_counts_toward_outer():
    source = (
        "def outer(x):\n"
        "    def inner(y):\n"
        "        if y:\n"
        "            return 1\n"
        "        return 0\n"
        "    return inner(x)\n"
    )

    assert only(source).complexity == 2


def test_try_finally_with_and_assert_add_nothing():
    source = (
        "def f(x):\n"
        "    assert x\n"
        "    with open(x):\n"
        "        pass\n"
        "    try:\n"
        "        pass\n"
        "    finally:\n"
        "        pass\n"
    )

    assert only(source).complexity == 1


def test_match_cases_count_but_wildcard_does_not():
    source = (
        "def f(x):\n"
        "    match x:\n"
        "        case 1:\n"
        "            return 1\n"
        "        case 2:\n"
        "            return 2\n"
        "        case _:\n"
        "            return 0\n"
    )

    assert only(source).complexity == 3


def test_branches_is_complexity_minus_one():
    metrics = FunctionMetrics("f", "example.py", 1, 3, 4, 1)

    assert metrics.branches == 3


# ----------------------------------------------------------------------
# Nesting depth
# ----------------------------------------------------------------------


def test_no_control_flow_has_no_nesting():
    source = "def f():\n    x = 1\n    return x\n"

    assert only(source).nesting == 0


def test_single_if_has_nesting_one():
    source = "def f(x):\n    if x:\n        return 1\n"

    assert only(source).nesting == 1


def test_if_inside_loop():
    source = (
        "def f(items):\n"
        "    for item in items:\n"
        "        if item:\n"
        "            pass\n"
    )

    assert only(source).nesting == 2


def test_elif_chain_stays_on_one_level():
    source = (
        "def f(x):\n"
        "    if x == 1:\n"
        "        pass\n"
        "    elif x == 2:\n"
        "        pass\n"
        "    elif x == 3:\n"
        "        pass\n"
        "    else:\n"
        "        pass\n"
    )

    assert only(source).nesting == 1


def test_nesting_inside_else_branch():
    source = (
        "def f(x, items):\n"
        "    if x:\n"
        "        pass\n"
        "    else:\n"
        "        for item in items:\n"
        "            if item:\n"
        "                pass\n"
    )

    assert only(source).nesting == 3


def test_with_for_if():
    source = (
        "def f(path):\n"
        "    with open(path) as handle:\n"
        "        for line in handle:\n"
        "            if line:\n"
        "                pass\n"
    )

    assert only(source).nesting == 3


def test_if_inside_except_handler():
    source = (
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError:\n"
        "        if True:\n"
        "            pass\n"
    )

    assert only(source).nesting == 2


def test_if_inside_match_case():
    source = (
        "def f(x):\n"
        "    match x:\n"
        "        case 1:\n"
        "            if x:\n"
        "                pass\n"
    )

    assert only(source).nesting == 2


def test_nested_function_adds_no_level_itself():
    source = (
        "def outer(x):\n"
        "    def inner(y):\n"
        "        if y:\n"
        "            pass\n"
    )

    assert only(source).nesting == 1


# ----------------------------------------------------------------------
# Functions and methods
# ----------------------------------------------------------------------


def test_module_function_metrics():
    source = "x = 1\n\ndef hello():\n    return 1\n"

    assert only(source) == FunctionMetrics(
        "hello",
        "example.py",
        3,
        2,
        1,
        0,
    )


def test_methods_have_qualified_names():
    source = (
        "class User:\n"
        "    def save(self):\n"
        "        pass\n"
        "\n"
        "    def delete(self):\n"
        "        pass\n"
    )

    metrics = analyze_complexity_source(source, "example.py")

    assert [(f.name, f.line) for f in metrics.functions] == [
        ("User.save", 2),
        ("User.delete", 5),
    ]


def test_nested_class_methods():
    source = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def run(self):\n"
        "            pass\n"
    )

    metrics = analyze_complexity_source(source, "example.py")

    assert [f.name for f in metrics.functions] == ["Outer.Inner.run"]


def test_async_function_is_measured():
    source = "async def fetch():\n    return 1\n"

    assert only(source).name == "fetch"


def test_nested_functions_are_not_listed_separately():
    source = (
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
        "    return inner\n"
    )

    metrics = analyze_complexity_source(source, "example.py")

    assert [f.name for f in metrics.functions] == ["outer"]


def test_decorated_function_starts_at_def_line():
    source = "@decorator\ndef f():\n    pass\n"

    function = only(source)

    assert function.line == 2
    assert function.lines == 2


def test_functions_follow_source_order():
    source = "def b():\n    pass\n\ndef a():\n    pass\n"

    metrics = analyze_complexity_source(source, "example.py")

    assert [f.name for f in metrics.functions] == ["b", "a"]


# ----------------------------------------------------------------------
# File metrics
# ----------------------------------------------------------------------


def test_counts_functions_and_classes():
    source = (
        "class A:\n"
        "    class B:\n"
        "        pass\n"
        "\n"
        "    def one(self):\n"
        "        pass\n"
        "\n"
        "def two():\n"
        "    pass\n"
    )

    metrics = analyze_complexity_source(source, "example.py")

    assert metrics.class_count == 2
    assert metrics.function_count == 2


def test_lines_of_code_skips_blank_and_comment_lines():
    source = (
        "# comment\n"
        "\n"
        "import os\n"
        "\n"
        "\n"
        "def f():\n"
        "    # inside\n"
        "    return os.getcwd()\n"
    )

    assert analyze_complexity_source(source, "e.py").lines_of_code == 3


def test_file_maximums():
    source = (
        "def simple():\n"
        "    return 1\n"
        "\n"
        "def busy(items):\n"
        "    for item in items:\n"
        "        if item:\n"
        "            return item\n"
        "    return None\n"
    )

    metrics = analyze_complexity_source(source, "example.py")

    assert metrics.max_complexity == 3
    assert metrics.max_nesting == 2


def test_file_without_functions_has_zero_maximums():
    metrics = analyze_complexity_source("X = 1\n", "example.py")

    assert metrics.function_count == 0
    assert metrics.max_complexity == 0
    assert metrics.max_nesting == 0


def test_empty_source():
    metrics = analyze_complexity_source("", "example.py")

    assert metrics.lines_of_code == 0
    assert metrics.class_count == 0
    assert metrics.function_count == 0


def test_invalid_source_raises_analysis_error():
    with pytest.raises(AnalysisError, match="Invalid Python syntax"):
        analyze_complexity_source("def broken(:\n", "example.py")


def test_analyze_complexity_from_file(tmp_path):
    target = write(tmp_path, "example.py", "def f():\n    pass\n")

    metrics = analyze_complexity(target)

    assert metrics.file == str(target)
    assert metrics.function_count == 1


def test_missing_file_raises_file_error(tmp_path):
    with pytest.raises(FileError):
        analyze_complexity(tmp_path / "missing.py")


def test_broken_file_raises_analysis_error(tmp_path):
    broken = write(tmp_path, "broken.py", "def broken(:\n")

    with pytest.raises(AnalysisError):
        analyze_complexity(broken)


# ----------------------------------------------------------------------
# Project metrics
# ----------------------------------------------------------------------


def test_project_totals(tmp_path):
    write(tmp_path, "a.py", "def simple():\n    return 1\n")
    write(
        tmp_path,
        "b.py",
        "class Tool:\n"
        "    def run(self, items):\n"
        "        for item in items:\n"
        "            if item:\n"
        "                return item\n"
        "        return None\n",
    )

    project = analyze_project_complexity(tmp_path)

    assert project.python_files == 2
    assert project.function_count == 2
    assert project.class_count == 1
    assert project.lines_of_code == 8
    assert project.max_complexity == 3
    assert project.max_nesting == 2


def test_project_file_names_are_relative(tmp_path):
    write(tmp_path, "pkg/util.py", "def helper():\n    pass\n")

    project = analyze_project_complexity(tmp_path)

    assert [item.file for item in project.files] == ["pkg/util.py"]
    assert project.most_complex()[0].file == "pkg/util.py"


def test_project_skips_broken_files(tmp_path):
    write(tmp_path, "broken.py", "def broken(:\n")
    write(tmp_path, "good.py", "def fine():\n    pass\n")

    project = analyze_project_complexity(tmp_path)

    assert project.python_files == 1
    assert project.skipped == ("broken.py",)


def test_project_ignores_pycache(tmp_path):
    write(
        tmp_path,
        "__pycache__/cached.py",
        "def helper():\n    pass\n",
    )

    project = analyze_project_complexity(tmp_path)

    assert project.python_files == 0
    assert project.skipped == ()


def test_empty_project(tmp_path):
    project = analyze_project_complexity(tmp_path)

    assert project.python_files == 0
    assert project.function_count == 0
    assert project.max_complexity == 0
    assert project.max_nesting == 0
    assert project.most_complex() == []


def test_most_complex_orders_worst_first(tmp_path):
    write(
        tmp_path,
        "a.py",
        "def alpha(x):\n    if x:\n        return 1\n    return 0\n",
    )
    write(
        tmp_path,
        "b.py",
        "def beta(x):\n    if x:\n        return 1\n    return 0\n",
    )
    write(
        tmp_path,
        "c.py",
        "def gamma(x):\n"
        "    if x:\n"
        "        if x > 1:\n"
        "            return 2\n"
        "    return 0\n",
    )

    project = analyze_project_complexity(tmp_path)

    assert [f.name for f in project.most_complex()] == [
        "gamma",
        "alpha",
        "beta",
    ]
    assert [f.name for f in project.most_complex(limit=2)] == [
        "gamma",
        "alpha",
    ]
