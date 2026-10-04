import os
import subprocess
import sys
from pathlib import Path

import pytest

from xray.errors import FileError
from xray.shellmetrics import analyze_shell_metrics, shell_metrics_lines

REPO = Path(__file__).resolve().parent.parent

SAMPLE = """#!/bin/sh
# a comment
greet() {
  if [ -n "$1" ]; then
    echo "if for while"
  fi
}
for x in a b; do
  case $x in
    a) greet a ;;
    b) greet b ;;
  esac
done
"""


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def run_xray(cwd, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_metrics_of_sample_script(tmp_path):
    metrics = analyze_shell_metrics(write(tmp_path / "t.sh", SAMPLE))

    assert metrics.lines_of_code == 11
    assert metrics.complexity == 5
    assert metrics.nesting == 2


def test_function_metrics(tmp_path):
    metrics = analyze_shell_metrics(write(tmp_path / "t.sh", SAMPLE))

    assert [f.name for f in metrics.functions] == ["greet"]

    greet = metrics.functions[0]

    assert greet.line == 3
    assert greet.lines == 5
    assert greet.complexity == 2
    assert greet.nesting == 1


def test_and_or_count_as_branches(tmp_path):
    script = write(tmp_path / "t.sh", "#!/bin/sh\ntrue && false || true\n")

    assert analyze_shell_metrics(script).complexity == 3


def test_heredoc_body_is_ignored(tmp_path):
    script = write(
        tmp_path / "t.sh",
        "#!/bin/sh\ncat <<EOF\nif for while\nEOF\n",
    )

    assert analyze_shell_metrics(script).complexity == 1


def test_hash_in_expansion_is_not_a_comment(tmp_path):
    script = write(
        tmp_path / "t.sh",
        "#!/bin/sh\necho $# && true\n# if for while\n",
    )

    assert analyze_shell_metrics(script).complexity == 2


def test_missing_file_raises_file_error(tmp_path):
    with pytest.raises(FileError):
        analyze_shell_metrics(tmp_path / "nope.sh")


def test_view_lines(tmp_path):
    lines = shell_metrics_lines(write(tmp_path / "t.sh", SAMPLE))

    assert "Lines of code:      11" in lines
    assert any(line.startswith("- greet: complexity 2") for line in lines)
    assert lines[-1].startswith("Note: approximate")


def test_cli_shell_metrics(tmp_path):
    script = write(tmp_path / "tool", SAMPLE)

    result = run_xray(tmp_path, str(script), "--shell-metrics")

    assert result.returncode == 0
    assert "Lines of code:" in result.stdout
    assert "greet" in result.stdout


def test_cli_rejects_non_shell_file(tmp_path):
    source = write(tmp_path / "a.py", "x = 1\n")

    result = run_xray(tmp_path, str(source), "--shell-metrics")

    assert result.returncode == 3
    assert "Not a shell script" in result.stderr
