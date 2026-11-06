from xray.evidence import build_evidence_graph
from xray.shellscan import facts_of_text, scan_shell
from xray.shparse import parse


def facts(text):
    return facts_of_text("#!/bin/sh\n" + text)


def test_case_patterns_are_not_commands():
    found = facts(
        'case "$DE" in\n'
        "  xfce|xfce4) xfconf-query ;;\n"
        "  kde)\n"
        "    kreadconfig\n"
        "    ;;\n"
        "  *) ;;\n"
        "esac\n"
    )

    assert sorted(found.commands) == ["kreadconfig", "xfconf-query"]


def test_getopts_style_case_with_options():
    found = facts(
        "while getopts 'nrV' opt; do\n"
        "  case $opt in\n"
        "    n) dry=1 ;;\n"
        "    V) print_version ;;\n"
        "  esac\n"
        "done\n"
    )

    assert sorted(found.commands) == ["print_version"]


def test_case_inside_command_substitution():
    found = facts("x=$(case a in a) date ;; b) uname ;; esac)\nls\n")

    assert sorted(found.commands) == ["date", "ls", "uname"]


def test_lines_are_reported_for_every_use():
    found = facts("ls\necho\nls -l \\\n  /tmp\nif true; then\n  ls\nfi\n")

    assert found.commands["ls"] == [2, 4, 7]


def test_multi_line_constructs():
    found = facts(
        "result=$(\n"
        "  grep -r x . |\n"
        "    sort -u\n"
        ")\n"
        "items=(\n"
        "  $(find . -name '*.c')\n"
        ")\n"
        "{\n"
        "  date\n"
        "} > log\n"
    )

    assert found.commands == {"date": [10], "find": [7], "grep": [3], "sort": [4]}


def test_unquoted_heredoc_substitutions_run_and_quoted_ones_do_not():
    found = facts(
        "cat <<EOF\n"
        "host $(hostname) kernel `uname -r`\n"
        "EOF\n"
        "cat <<'EOF'\n"
        "$(not-run)\n"
        "EOF\n"
        "cat <<-\tEND\n"
        "\t$(id)\n"
        "\tEND\n"
    )

    assert sorted(found.commands) == ["cat", "hostname", "id", "uname"]


def test_trap_and_sh_c_strings_are_read_as_code():
    found = facts("trap 'rm -f \"$tmp\"' EXIT\nbash -ec 'id -u; whoami'\n")

    assert sorted(found.commands) == ["bash", "id", "rm", "whoami"]
    assert found.via == {"rm": "trap", "id": "bash -c", "whoami": "bash -c"}


def test_sh_c_with_a_variable_is_dynamic():
    found = facts('sh -c "$cmd"\n')

    assert sorted(found.commands) == ["sh"]
    assert [word for _, word in found.dynamic] == ['sh -c "$cmd"']


def test_command_v_is_a_lookup_not_a_run():
    found = facts("command -v jq >/dev/null\ncommand -p ls\n")

    assert sorted(found.commands) == ["ls"]


def test_substitutions_in_parameter_defaults_and_tests():
    found = facts('y=${HOME:-$(getent passwd me)}\n[[ $(stat -c %s f) -gt 0 ]] && touch z\n')

    assert sorted(found.commands) == ["getent", "stat", "touch"]


def test_process_substitution_after_done():
    found = facts("while read -r l; do echo $l; done < <(lsblk -n)\n")

    assert sorted(found.commands) == ["lsblk"]


def test_variables_assigned_fixed_values_are_resolved_as_guesses():
    found = facts(
        "TERM_CMD=(foot -e)\n"
        "g=/usr/bin/grep\n"
        '"${TERM_CMD[@]}" bash\n'
        "$g -q x f\n"
        "$unknown y\n"
    )

    assert sorted(found.commands) == ["/usr/bin/grep", "foot"]
    assert found.via == {"foot": "$TERM_CMD", "/usr/bin/grep": "$g"}
    assert found.dynamic == ((6, "$unknown"),)


def test_variables_with_any_unknown_value_stay_dynamic():
    found = facts('tool=gzip\n[ -n "$x" ] && tool=$1\n$tool f\n')

    assert found.commands == {}
    assert len(found.dynamic) == 1


def test_path_assignments_are_found_with_lines():
    found = facts("export PATH=/opt/bin:$PATH\nPATH+=:/x\nls\nlocal PATH=/y\n")

    assert found.path_lines == (2, 3, 5)


def test_functions_with_and_without_keyword():
    found = facts("a() { ls; }\nfunction b {\n  date\n}\nfunction c() ( id )\na\nb\n")

    assert found.functions == {"a": 2, "b": 3, "c": 6}
    assert sorted(found.commands) == ["date", "id", "ls"]


def test_arithmetic_and_extglob_are_not_commands():
    found = facts("(( i++ ))\nfor ((i=0; i<3; i++)); do :; done\n[[ $f == @(a|b) ]]\nls !(x)\n")

    assert sorted(found.commands) == ["ls"]


def test_redirections_of_every_form():
    found = facts("exec 3<>file 2>&1\n{fd}>out cmd-a\n&>/dev/null cmd-b\ncmd-c >| f <<< \"$(hostname)\"\n")

    assert sorted(found.commands) == ["cmd-a", "cmd-b", "cmd-c", "hostname"]


def test_ansi_c_quoted_command_is_static():
    found = facts("$'ls' -l\n")

    assert sorted(found.commands) == ["ls"]


def test_unterminated_input_does_not_raise():
    for text in ["echo \"unclosed\n", "x=$(ls\n", "case x in\n a)", "cat <<EOF\nno end\n", "${", "`ls", "((", "a=("]:
        parse(text)


def test_scan_shell_still_reports_sorted_unique_names(tmp_path):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\nzeta\nalpha\nzeta\n", encoding="utf-8")

    assert scan_shell(path).commands == ("alpha", "zeta")


def test_evidence_for_variable_command_is_guessed(tmp_path):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\nCMD=(ls -l)\n\"${CMD[@]}\"\n", encoding="utf-8")
    path.chmod(0o755)

    graph = build_evidence_graph(str(path), packages=False)
    link = graph.links[(str(path.resolve()), "command:ls", "runs")]

    assert link.basis == "guessed"
    assert link.evidence[0].line == 3
    assert "$CMD" in link.evidence[0].detail
