import subprocess
import sys

TARGET = "test_programs/cycle_a.py"


def run_xray(*args):
    result = subprocess.run(
        [sys.executable, "-m", "xray.cli", TARGET, *args],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr

    return result.stdout


def run_raw(*args):
    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_deps():
    output = run_xray("--deps")

    assert "Dependencies of test_programs/cycle_a.py" in output
    assert "test_programs/cycle_b.py" in output


def test_default_overview_suggests_next_queries():
    output = run_xray()

    assert "Explore this command" in output
    assert "xray test_programs/cycle_a.py --code" in output
    assert "--cycles" in output
    assert "--path <target>" in output


def test_dependents():
    output = run_xray("--dependents")

    assert "Dependents of test_programs/cycle_a.py" in output
    assert "test_programs/cycle_c.py" in output


def test_cycles():
    output = run_xray("--cycles")

    assert "Circular dependencies" in output
    assert "test_programs/cycle_a.py → test_programs/cycle_b.py" in output
    assert "Cycles" not in output


def test_depth():
    output = run_xray("--depth")

    assert "Dependency depth for test_programs/cycle_a.py" in output
    assert "Depth: 3" in output


def test_project():
    output = run_xray("--project")

    assert "Project" in output
    assert "Python files:      6" in output
    assert "Dependency edges:  3" in output
    assert "Leaf files:        3" in output
    assert "Cycles:            1" in output
    assert "Dependency hotspots" in output


def test_components():
    output = run_xray("--components")

    assert "Strongly connected components" in output
    assert "test_programs/cycle_a.py" in output
    assert "test_programs/cycle_b.py" in output
    assert "test_programs/cycle_c.py" in output


def test_reachable():
    output = run_xray("--reachable")

    assert "Reachable dependencies from test_programs/cycle_a.py" in output
    assert "test_programs/cycle_b.py" in output
    assert "test_programs/cycle_c.py" in output


def test_reverse_reachable():
    output = run_xray("--reverse-reachable")

    assert (
        "Reverse-reachable dependents of "
        "test_programs/cycle_a.py"
    ) in output
    assert "test_programs/cycle_b.py" in output
    assert "test_programs/cycle_c.py" in output


def test_help():
    result = run_raw("--help")

    assert result.returncode == 0
    assert "Usage" in result.stdout
    assert "--project" in result.stdout
    assert "--depth" in result.stdout
    assert "--components" in result.stdout
    assert "--reachable" in result.stdout
    assert "--reverse-reachable" in result.stdout
    assert "--changes" in result.stdout


def test_short_help():
    result = run_raw("-h")

    assert result.returncode == 0
    assert "Usage" in result.stdout


def test_no_arguments_shows_xray_self_overview_and_next_commands():
    result = run_raw()

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Explore this command" in result.stdout
    assert "xray xray/cli.py --code" in result.stdout
    assert "xray xray/cli.py --cycles" in result.stdout
    assert "xray xray/cli.py --path <target>" in result.stdout


def test_unknown_target():
    result = run_raw("definitely-not-a-command")

    assert result.returncode == 3
    assert result.stdout == ""
    assert (
        "Error: Command not found: definitely-not-a-command"
        in result.stderr
    )


def test_path():
    output = run_xray(
        "--path",
        "test_programs/cycle_c.py",
    )

    assert (
        "Dependency path from "
        "test_programs/cycle_a.py to "
        "test_programs/cycle_c.py"
    ) in output

    assert (
        "test_programs/cycle_a.py → "
        "test_programs/cycle_b.py → "
        "test_programs/cycle_c.py"
    ) in output


def test_path_same_node():
    output = run_xray(
        "--path",
        "test_programs/cycle_a.py",
    )

    assert "test_programs/cycle_a.py" in output


def test_path_missing_target():
    output = run_xray(
        "--path",
        "definitely-not-real.py",
    )

    assert "No path found" in output


def test_tree():
    output = run_xray("--tree")

    assert (
        "Dependency tree for "
        "test_programs/cycle_a.py"
    ) in output
    assert "test_programs/cycle_b.py" in output
    assert "test_programs/cycle_c.py" in output


def test_impact():
    output = run_xray("--impact")

    assert "Impact of removing test_programs/cycle_a.py" in output
    assert "Directly affected:" in output
    assert "Indirectly affected:" in output
    assert "Impact chains" in output
    assert "test_programs/cycle_c.py" in output


def test_cycles_does_not_report_false_positive():
    result = run_raw(
        "test_programs/standalone.py",
        "--cycles",
    )

    assert result.returncode == 0
    assert "Circular dependencies" in result.stdout
    assert "none" in result.stdout


def test_path_missing_argument():
    result = run_raw(
        TARGET,
        "--path",
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert (
        "Error: Usage: xray <target> --path <target>"
        in result.stderr
    )


def test_path_extra_argument():
    result = run_raw(
        TARGET,
        "--path",
        "test_programs/cycle_c.py",
        "extra",
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert (
        "Error: Usage: xray <target> --path <target>"
        in result.stderr
    )


def test_unknown_option():
    result = run_raw(
        TARGET,
        "--definitely-not-an-option",
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert (
        "Error: Unknown option: --definitely-not-an-option"
        in result.stderr
    )


def test_help_lists_all_queries():
    result = run_raw("--help")

    assert result.returncode == 0

    for option in (
        "--deps",
        "--dependents",
        "--tree",
        "--impact",
        "--cycles",
        "--depth",
        "--project",
        "--components",
        "--reachable",
        "--reverse-reachable",
        "--path",
    ):
        assert option in result.stdout


def test_module_help():
    result = subprocess.run(
        [sys.executable, "-m", "xray", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Usage: xray <target> [option] [option arguments]" in result.stdout


def test_invalid_python_reports_analysis_error(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text(
        "def broken(:\n",
        encoding="utf-8",
    )

    result = run_raw(str(broken))

    assert result.returncode == 4
    assert result.stdout == ""
    assert "Error: Invalid Python syntax:" in result.stderr


def test_missing_file_reports_target_error():
    result = run_raw(
        "definitely-not-real-xray-file.py"
    )

    assert result.returncode == 3
    assert result.stdout == ""
    assert (
        "Error: Command not found: "
        "definitely-not-real-xray-file.py"
    ) in result.stderr


def test_directory_target_reports_file_error(tmp_path):
    result = run_raw(str(tmp_path))

    assert result.returncode == 3
    assert result.stdout == ""
    assert "Error:" in result.stderr


def test_unreadable_python_reports_file_error(tmp_path):
    if hasattr(__import__("os"), "geteuid"):
        import os

        if os.geteuid() == 0:
            return

    unreadable = tmp_path / "unreadable.py"
    unreadable.write_text(
        "print('hello')\n",
        encoding="utf-8",
    )
    unreadable.chmod(0o000)

    try:
        result = run_raw(str(unreadable))

        assert result.returncode == 3
        assert result.stdout == ""
        assert "Error: Unable to read file:" in result.stderr
    finally:
        unreadable.chmod(0o644)


def test_extra_argument_after_query():
    result = run_raw(
        TARGET,
        "--deps",
        "extra",
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Error:" in result.stderr


def test_two_queries_are_rejected():
    result = run_raw(
        TARGET,
        "--deps",
        "--depth",
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Error:" in result.stderr


def test_unknown_leading_option():
    result = run_raw("--bad-option")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Error: Unknown option: --bad-option" in result.stderr


ALL_QUERIES = (
    "--deps",
    "--dependents",
    "--tree",
    "--impact",
    "--cycles",
    "--depth",
    "--project",
    "--components",
    "--reachable",
    "--reverse-reachable",
)


def test_non_python_target_queries_do_not_crash(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("hello\n", encoding="utf-8")

    solo = tmp_path / "solo.py"
    solo.write_text("print('hi')\n", encoding="utf-8")

    for query in ALL_QUERIES:
        result = run_raw(str(notes), query)

        assert result.returncode == 0, (query, result.stderr)
        assert result.stderr == ""
        assert "Traceback" not in result.stdout


def test_path_to_unknown_node_reports_no_path(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("hello\n", encoding="utf-8")

    solo = tmp_path / "solo.py"
    solo.write_text("print('hi')\n", encoding="utf-8")

    result = run_raw(str(solo), "--path", str(notes))

    assert result.returncode == 0
    assert result.stderr == ""
    assert "No path found" in result.stdout


def test_empty_graph_queries_do_not_crash(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("hello\n", encoding="utf-8")

    for query in ALL_QUERIES:
        result = run_raw(str(notes), query)

        assert result.returncode == 0, (query, result.stderr)
        assert result.stderr == ""

    project = run_raw(str(notes), "--project")

    assert "Python files:      0" in project.stdout
    assert "Dependency edges:  0" in project.stdout


def test_broken_sibling_does_not_break_analysis(tmp_path):
    good = tmp_path / "a.py"
    good.write_text("import b\n", encoding="utf-8")

    broken = tmp_path / "b.py"
    broken.write_text("def broken(:\n", encoding="utf-8")

    for query in ("--deps", "--project", "--cycles"):
        result = run_raw(str(good), query)

        assert result.returncode == 0, (query, result.stderr)

    deps = run_raw(str(good), "--deps")

    assert "b.py" in deps.stdout


def test_broken_target_with_query_still_reports_error(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")

    result = run_raw(str(broken), "--deps")

    assert result.returncode == 4
    assert result.stdout == ""
    assert "Invalid Python syntax" in result.stderr


def test_extensionless_python_command_dependencies(tmp_path):
    helper = tmp_path / "helper.py"
    helper.write_text(
        "def greet():\n"
        "    return 'hi'\n"
    )

    command = tmp_path / "mytool"
    command.write_text(
        "#!/usr/bin/env python3\n"
        "from helper import greet\n"
        "greet()\n"
    )

    result = run_raw(str(command), "--deps")

    assert result.returncode == 0
    assert "helper.py" in result.stdout


def test_inspect_combines_report_sections():
    output = run_xray("--inspect")

    assert "Inspection of" in output
    assert "Identity" in output
    assert "Overview" in output
    assert "Source files" in output


def test_inspect_markdown():
    result = run_raw(TARGET, "--inspect", "--md")

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("# Inspection:")
    assert "## Identity" in result.stdout
    assert "## Overview" in result.stdout


def test_inspect_rejects_unknown_extra_arguments():
    result = run_raw(TARGET, "--inspect", "--unknown")

    assert result.returncode == 2
    assert "Usage: xray" in result.stderr
