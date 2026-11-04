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
    lines = calls_lines(write(tmp_path, '$grep -H x\neval "ls $d"\n'))

    assert (
        "Commands run through variables or eval (not resolved): 2" in lines
    )


def test_calls_lines_have_no_extra_line_without_them(tmp_path):
    lines = calls_lines(write(tmp_path, "echo hi\n"))

    assert not any("variables or eval" in line for line in lines)


def test_literal_eval_is_read_as_shell_code(tmp_path):
    scan = scan_shell(write(tmp_path, 'eval "gzip -d x | tar xf -"\n'))

    assert scan.commands == ("gzip", "tar")
    assert scan.dynamic == 0


def test_wrapped_commands_are_reported(tmp_path):
    scan = scan_shell(write(
        tmp_path,
        "sudo -u root systemctl restart x\n"
        "env -i LANG=C sort f\n"
        "timeout -s KILL 5 curl url\n"
        "xargs -I {} -P 4 gzip {} < list\n"
        "find . -name '*.o' -exec rm {} \\; -execdir strip {} +\n"
        "nice -n 5 make\n",
    ))

    assert set(scan.commands) == {
        "sudo", "systemctl", "env", "sort", "timeout", "curl", "xargs",
        "gzip", "find", "rm", "strip", "nice", "make",
    }


def test_process_substitution_is_read_and_not_mistaken_for_commands(tmp_path):
    scan = scan_shell(write(tmp_path, "diff <(sort a) >(tee b) /dev/null\n"))

    assert scan.commands == ("diff", "sort", "tee")
