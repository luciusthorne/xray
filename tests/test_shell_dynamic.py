from xray.calls import calls_lines
from xray.shellscan import ShellScan, scan_shell


def write(tmp_path, body):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def test_variable_command_is_counted(tmp_path):
    assert scan_shell(write(tmp_path, "$grep -H x\n")).dynamic == 1


def test_quoted_variable_command_is_counted(tmp_path):
    assert scan_shell(write(tmp_path, '"$cmd" a b\n')).dynamic == 1


def test_variable_after_an_assignment_prefix_is_counted(tmp_path):
    assert scan_shell(write(tmp_path, "LC_ALL=C $tool x\n")).dynamic == 1


def test_eval_is_counted(tmp_path):
    assert scan_shell(write(tmp_path, 'eval "ls $d"\n')).dynamic == 1


def test_ordinary_uses_of_variables_are_not_counted(tmp_path):
    body = 'echo $x\nx=$(ls)\nls "$d"\ngrep -r "$p" .\n'

    assert scan_shell(write(tmp_path, body)).dynamic == 0


def test_dynamic_is_not_part_of_equality(tmp_path):
    scan = scan_shell(write(tmp_path, "$a\nls\n"))

    assert scan == ShellScan((), (), ("ls",))
    assert scan.dynamic == 1


def test_calls_lines_report_the_count(tmp_path):
    lines = calls_lines(write(tmp_path, '$grep -H x\neval "ls"\n'))

    assert (
        "Commands run through variables or eval (not resolved): 2" in lines
    )


def test_calls_lines_have_no_extra_line_without_them(tmp_path):
    lines = calls_lines(write(tmp_path, "echo hi\n"))

    assert not any("variables or eval" in line for line in lines)
