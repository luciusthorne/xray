from xray.command_analyzers import ShellAnalyzer
from xray.symbols import Symbol


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def summary(symbols):
    return [(s.name, s.kind, s.line) for s in symbols]


def test_functions_become_symbols_with_lines(tmp_path):
    script = write(
        tmp_path / "tool.sh",
        "#!/bin/sh\n"
        "helper() {\n"
        "  echo hi\n"
        "}\n"
        "function other {\n"
        "  :\n"
        "}\n",
    )

    assert summary(ShellAnalyzer().symbols(script)) == [
        ("helper", "function", 2),
        ("other", "function", 5),
    ]


def test_lines_are_correct_after_a_heredoc(tmp_path):
    script = write(
        tmp_path / "tool.sh",
        "#!/bin/sh\n"
        "cat <<EOF\n"
        "fake() {\n"
        "EOF\n"
        "real() {\n"
        "  :\n"
        "}\n",
    )

    assert summary(ShellAnalyzer().symbols(script)) == [
        ("real", "function", 5),
    ]


def test_lines_are_correct_after_a_continuation(tmp_path):
    script = write(
        tmp_path / "tool.sh",
        "#!/bin/sh\n"
        "echo a \\\n"
        "  b\n"
        "late() {\n"
        "  :\n"
        "}\n",
    )

    assert summary(ShellAnalyzer().symbols(script)) == [
        ("late", "function", 4),
    ]


def test_symbol_records_name_the_resolved_file(tmp_path):
    script = write(tmp_path / "tool.sh", "#!/bin/sh\nf() {\n  :\n}\n")

    symbols = ShellAnalyzer().symbols(script)

    assert symbols == [Symbol("f", "function", str(script.resolve()), 2)]


def test_no_functions_or_missing_file_give_nothing(tmp_path):
    script = write(tmp_path / "tool.sh", "#!/bin/sh\necho hi\n")

    assert ShellAnalyzer().symbols(script) == []
    assert ShellAnalyzer().symbols(tmp_path / "missing.sh") == []
