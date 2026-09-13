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
