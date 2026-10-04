import pytest

from xray.analysis_views import (
    complexity_lines,
    references_lines,
    relationships_lines,
    symbols_lines,
    unused_lines,
)


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def test_symbols_lines_lists_definitions(tmp_path):
    source = write(
        tmp_path / "example.py",
        "import os\n"
        "\n"
        "\n"
        "def hello():\n"
        "    return os.getcwd()\n"
        "\n"
        "\n"
        "class User:\n"
        "    def save(self):\n"
        "        hello()\n",
    )

    lines = symbols_lines(source)

    assert "- function: hello (line 4)" in lines
    assert "- class: User (line 8)" in lines
    assert "- method: User.save (line 9)" in lines


@pytest.mark.parametrize(
    "view",
    [symbols_lines, references_lines, relationships_lines, unused_lines],
)
def test_empty_file_gives_none(tmp_path, view):
    source = write(tmp_path / "empty.py")

    assert view(source) == ["none"]


def test_unused_lines_reports_unused_import(tmp_path):
    source = write(
        tmp_path / "a.py",
        "import json\nimport os\n\nos.getcwd()\n",
    )

    lines = unused_lines(source)
    items = [line for line in lines if line.startswith("- ")]

    assert len(items) == 1
    assert items[0].startswith("- json (line 1)")
    assert lines[-1].startswith("Static analysis result")


def test_unused_lines_none_when_everything_is_used(tmp_path):
    source = write(tmp_path / "a.py", "import os\n\nos.getcwd()\n")

    assert unused_lines(source) == ["none"]


def test_complexity_lines_most_complex_first(tmp_path):
    source = write(
        tmp_path / "a.py",
        "def simple():\n"
        "    return 1\n"
        "\n"
        "\n"
        "def branchy(x):\n"
        "    if x:\n"
        "        return 1\n"
        "    return 2\n",
    )

    lines = complexity_lines(source)
    items = [line for line in lines if line.startswith("- ")]

    assert lines[1].startswith("Functions:")
    assert lines[1].split()[-1] == "2"
    assert int(lines[3].split()[-1]) >= 2
    assert items[0].startswith("- branchy: complexity ")
    assert items[1].startswith("- simple: complexity 1,")


def test_complexity_lines_without_functions(tmp_path):
    source = write(tmp_path / "a.py", "x = 1\n")

    lines = complexity_lines(source)

    assert lines[1].split()[-1] == "0"
    assert lines[3].split()[-1] == "0"
    assert lines[-1] == "- none"


def test_references_lines_resolve_to_the_defining_file(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "from utils import calculate\n\ncalculate()\n",
    )

    lines = references_lines(main)
    matches = [
        line for line in lines if line.startswith("- calculate (line 3)")
    ]

    assert matches
    assert "utils.py" in matches[0]


def test_relationships_lines_show_calls(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "from utils import calculate\n"
        "\n"
        "\n"
        "def main():\n"
        "    calculate()\n",
    )

    lines = relationships_lines(main)
    matches = [
        line
        for line in lines
        if line.startswith("- calls: main -> calculate (line 5)")
    ]

    assert matches
    assert "utils.py" in matches[0]
