from xray.shellscan import scan_shell


def count(tmp_path, body):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")

    return scan_shell(path).dynamic


def test_sed_script_tail_is_not_a_command(tmp_path):
    body = "sed '\n  $s/$/'\\''/\n' file\n"

    assert count(tmp_path, body) == 0


def test_clean_variable_commands_still_count(tmp_path):
    assert count(tmp_path, "$grep -H x\n") == 1
    assert count(tmp_path, '"$cmd" a\n') == 1
    assert count(tmp_path, "${tool} a\n") == 1
    assert count(tmp_path, "${POSIXLY_CORRECT+break}\n") == 1


def test_eval_still_counts(tmp_path):
    assert count(tmp_path, 'eval "ls $d"\n') == 1


def test_positional_parameter_in_command_position_counts(tmp_path):
    assert count(tmp_path, "$1 x\n") == 1


def test_boolean_variable_tests_are_counted(tmp_path):
    # "if $flag" runs the variable as a command. A static reader cannot
    # tell a boolean idiom from a hidden command, so it is counted.
    assert count(tmp_path, "if $flag; then ls; fi\n") == 1
