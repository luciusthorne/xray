import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

FAKE_STRACE = (
    "#!/bin/sh\n"
    'echo "$@" > "$ARGS_OUT"\n'
    'while [ "$1" != "-o" ]; do shift; done\n'
    "printf '100 execve(\"/usr/bin/tool\", [\"tool\"], 0x0 /* 1 vars */)"
    " = 0\\n' > \"$2\"\n"
    "exit 0\n"
)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)

    return path


def run_xray(cwd, path_value, *args, extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    env["PATH"] = path_value
    env.update(extra or {})

    return subprocess.run(
        [sys.executable, "-m", "xray.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def with_fake(tmp_path):
    bindir = tmp_path / "fakebin"
    write(bindir / "strace", FAKE_STRACE)

    return str(bindir) + os.pathsep + os.environ["PATH"]


def test_cli_trace_shows_the_report_and_passes_arguments(tmp_path):
    tool = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")
    args_file = tmp_path / "args.txt"

    result = run_xray(
        tmp_path,
        with_fake(tmp_path),
        str(tool),
        "--trace",
        "--",
        "a1",
        "a2",
        extra={"ARGS_OUT": str(args_file)},
    )

    assert result.returncode == 0
    assert "Trace of tool" in result.stdout
    assert "- /usr/bin/tool" in result.stdout
    assert "Exit status: 0" in result.stdout
    assert args_file.read_text(encoding="utf-8").split()[-2:] == ["a1", "a2"]


def test_cli_trace_with_an_empty_trace_exits_4(tmp_path):
    bindir = tmp_path / "fakebin"
    write(bindir / "strace", "#!/bin/sh\nexit 1\n")
    tool = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(
        tmp_path,
        str(bindir) + os.pathsep + os.environ["PATH"],
        str(tool),
        "--trace",
    )

    assert result.returncode == 4
    assert "no trace" in result.stderr


def test_cli_trace_rejects_arguments_without_double_dash(tmp_path):
    tool = write(tmp_path / "tool", "#!/bin/sh\necho hi\n")

    result = run_xray(
        tmp_path, with_fake(tmp_path), str(tool), "--trace", "extra"
    )

    assert result.returncode == 2
    assert "Usage" in result.stderr


def test_help_mentions_trace(tmp_path):
    result = run_xray(tmp_path, os.environ["PATH"], "--help")

    assert "--trace" in result.stdout
