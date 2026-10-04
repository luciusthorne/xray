from xray.shellscan import ShellScan, scan_shell


def script(tmp_path, text):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\n" + text, encoding="utf-8")

    return path


def test_clevis_style_script(tmp_path):
    path = script(
        tmp_path,
        "# vim: set tabstop=8\n"
        '[ $# -eq 1 ] && [ "$1" == "--summary" ] && exit 2\n'
        "if [ -t 0 ]; then\n"
        "    exec >&2\n"
        "    echo\n"
        "    exit 2\n"
        "fi\n"
        "read -r -d . hdr\n"
        'if ! jhd="$(jose b64 dec -i- <<< "$hdr")"; then\n'
        '    echo "bad" >&2\n'
        "    exit 1\n"
        "fi\n"
        'if [ "$(jose fmt -j- -Og clevis -g pin -u- <<< "$jhd")" != "tang" ]; then\n'
        "    exit 1\n"
        "fi\n"
        "CLEVIS_DEFAULT_THP_ALG=S256       # SHA-256.\n",
    )

    assert scan_shell(path) == ShellScan((), (), ("jose",))


def test_functions_are_listed_and_not_commands(tmp_path):
    path = script(
        tmp_path,
        "greet() {\n"
        "    echo hi\n"
        "}\n"
        "function other {\n"
        "    ls\n"
        "}\n"
        "greet\n",
    )

    assert scan_shell(path) == ShellScan(("greet", "other"), (), ("ls",))


def test_sources(tmp_path):
    path = script(
        tmp_path,
        '. ./lib.sh\nsource "$DIR/util.sh"\n',
    )

    assert scan_shell(path) == ShellScan(
        (), ("$DIR/util.sh", "./lib.sh"), ()
    )


def test_pipes_and_lists(tmp_path):
    path = script(tmp_path, "cat f | grep x && sort -u || tail\n")

    assert scan_shell(path).commands == ("cat", "grep", "sort", "tail")


def test_command_substitution(tmp_path):
    path = script(
        tmp_path,
        "x=$(date +%s)\n"
        "y=`hostname`\n"
        'echo "$(whoami)"\n',
    )

    assert scan_shell(path).commands == ("date", "hostname", "whoami")


def test_comments_are_ignored(tmp_path):
    path = script(tmp_path, "# git status\necho hi # rm -rf\n")

    assert scan_shell(path).commands == ()


def test_heredoc_body_is_ignored(tmp_path):
    path = script(tmp_path, "cat <<EOF\nrm -rf /\nEOF\nls\n")

    assert scan_shell(path).commands == ("cat", "ls")


def test_here_string_is_not_a_heredoc(tmp_path):
    path = script(tmp_path, 'grep x <<< "$v"\nls\n')

    assert scan_shell(path).commands == ("grep", "ls")


def test_keywords_are_stripped(tmp_path):
    path = script(
        tmp_path,
        "if curl -s x; then\n"
        "    wget y\n"
        "else\n"
        "    fetch z\n"
        "fi\n",
    )

    assert scan_shell(path).commands == ("curl", "fetch", "wget")


def test_env_prefix_and_exec(tmp_path):
    path = script(tmp_path, "LANG=C sort file\nexec python3 main.py\n")

    assert scan_shell(path).commands == ("python3", "sort")


def test_builtins_are_filtered(tmp_path):
    path = script(
        tmp_path,
        "cd /tmp\n"
        "export A=1\n"
        "local b\n"
        "set -e\n"
        "trap x EXIT\n"
        "[ -f x ]\n"
        "[[ -n y ]]\n"
        "test -d z\n"
        "true\n"
        "return 0\n",
    )

    assert scan_shell(path).commands == ()


def test_redirections(tmp_path):
    path = script(
        tmp_path,
        "exec >&2\n"
        "echo hi 2>&1\n"
        "ls >/dev/null 2>&1\n",
    )

    assert scan_shell(path).commands == ("ls",)


def test_case_patterns(tmp_path):
    path = script(
        tmp_path,
        'case "$1" in\n'
        "  start)\n"
        "    run-it\n"
        "    ;;\n"
        "  stop|halt) stopper ;;\n"
        "  *) usage ;;\n"
        "esac\n",
    )

    assert scan_shell(path).commands == ("run-it", "stopper", "usage")


def test_line_continuation(tmp_path):
    path = script(tmp_path, "docker run \\\n  --rm image\n")

    assert scan_shell(path).commands == ("docker",)


def test_arithmetic(tmp_path):
    path = script(tmp_path, "(( i++ ))\nx=$((1 + 2))\nls\n")

    assert scan_shell(path).commands == ("ls",)


def test_nested_substitution(tmp_path):
    path = script(tmp_path, 'echo "$(basename "$(hostname)")"\n')

    assert scan_shell(path).commands == ("basename", "hostname")


def test_missing_file_is_empty(tmp_path):
    assert scan_shell(tmp_path / "nope") == ShellScan()


def test_empty_file_is_empty(tmp_path):
    path = tmp_path / "tool"
    path.write_text("", encoding="utf-8")

    assert scan_shell(path) == ShellScan()


def test_dynamic_command_is_skipped(tmp_path):
    path = script(tmp_path, '$CMD arg\n"$other" x\nls\n')

    assert scan_shell(path).commands == ("ls",)


def test_results_are_sorted_and_unique(tmp_path):
    path = script(tmp_path, "zeta\nalpha\nzeta\n")

    assert scan_shell(path).commands == ("alpha", "zeta")


def test_case_patterns_with_spaces_around_pipes(tmp_path):
    path = script(
        tmp_path,
        "case $x in\n"
        "  / | /*/) ;;\n"
        "  a | b) run-it ;;\n"
        "esac\n",
    )

    assert scan_shell(path).commands == ("run-it",)


def test_subshell_pipeline_is_still_scanned(tmp_path):
    path = script(tmp_path, "(cat f | grep x)\nls\n")

    assert scan_shell(path).commands == ("cat", "grep", "ls")
