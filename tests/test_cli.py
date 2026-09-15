import subprocess
import sys


TARGET = "test_programs/cycle_a.py"


def run_xray(*args):
    result = subprocess.run(
        [sys.executable, "-m", "xray.cli", TARGET, *args],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    return result.stdout


def run_raw(*args):
    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        capture_output=True,
        text=True,
    )


def test_deps():
    output = run_xray("--deps")

    assert "Dependencies of test_programs/cycle_a.py" in output
    assert "test_programs/cycle_b.py" in output


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
    assert "Python files:      5" in output
    assert "Dependency edges:  3" in output
    assert "Leaf files:        2" in output
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


def test_short_help():
    result = run_raw("-h")

    assert result.returncode == 0
    assert "Usage" in result.stdout


def test_missing_target():
    result = run_raw()

    assert result.returncode != 0
    assert "Usage:" in result.stdout


def test_unknown_target():
    result = run_raw("definitely-not-a-command")

    assert result.returncode != 0
    assert "Command not found: definitely-not-a-command" in result.stdout
