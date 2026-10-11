import subprocess
from pathlib import Path

import pytest

import xray.trace as trace_module
from xray.errors import AnalysisError
from xray.trace import parse_trace, run_trace, trace_lines

TEXT = (
    '100 execve("/usr/bin/tool", ["tool"], 0x0 /* 1 vars */) = 0\n'
    '100 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3\n'
    '100 openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) = 3\n'
    '100 openat(AT_FDCWD, "/etc/data.conf", O_RDONLY) = 3\n'
    '100 openat(AT_FDCWD, "/etc/data.conf", O_RDONLY) = 3\n'
    '100 openat(AT_FDCWD, "/etc/missing.conf", O_RDONLY) = -1 ENOENT '
    "(No such file or directory)\n"
    '101 execve("/usr/bin/other", ["other"], 0x0 /* 1 vars */) = 0\n'
    '102 execve("/usr/bin/nope", ["nope"], 0x0 /* 1 vars */) = -1 ENOENT '
    "(No such file or directory)\n"
    "103 openat(AT_FDCWD, \"/etc/late.conf\", O_RDONLY <unfinished ...>\n"
)


def fake_run(text, returncode=0, timeout=False):
    def run(command, **kwargs):
        run.command = command
        Path(command[command.index("-o") + 1]).write_text(
            text, encoding="utf-8"
        )

        if timeout:
            raise subprocess.TimeoutExpired(command, 1)

        return subprocess.CompletedProcess(command, returncode)

    return run


def test_parse_collects_executed_opened_and_failed():
    result = parse_trace(TEXT)

    assert result.executed == ("/usr/bin/tool", "/usr/bin/other")
    assert result.opened == ("/etc/data.conf",)
    assert result.failed == 1


def test_run_passes_arguments_after_double_dash(tmp_path, monkeypatch):
    run = fake_run(TEXT)
    monkeypatch.setattr(trace_module.subprocess, "run", run)

    run_trace(tmp_path / "tool", ["a1", "a2"])

    command = run.command

    assert command[0] == "strace"
    assert command[command.index("--") + 1:] == [
        str(tmp_path / "tool"),
        "a1",
        "a2",
    ]


def test_timeout_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(
        trace_module.subprocess, "run", fake_run(TEXT, timeout=True)
    )

    result = run_trace(tmp_path / "tool", [], timeout=1)

    assert result.timed_out is True
    assert result.status is None
    assert result.executed == ("/usr/bin/tool", "/usr/bin/other")


def test_missing_strace_is_an_analysis_error(tmp_path, monkeypatch):
    def run(command, **kwargs):
        raise FileNotFoundError("strace")

    monkeypatch.setattr(trace_module.subprocess, "run", run)

    with pytest.raises(AnalysisError, match="strace"):
        run_trace(tmp_path / "tool", [])


def test_empty_trace_is_an_analysis_error(tmp_path, monkeypatch):
    monkeypatch.setattr(
        trace_module.subprocess, "run", fake_run("", returncode=1)
    )

    with pytest.raises(AnalysisError, match="no trace"):
        run_trace(tmp_path / "tool", [])


def test_trace_lines_format(tmp_path, monkeypatch):
    monkeypatch.setattr(trace_module.subprocess, "run", fake_run(TEXT))

    assert trace_lines(tmp_path / "tool") == [
        "Executed:",
        "- /usr/bin/tool",
        "- /usr/bin/other",
        "Opened:",
        "- /etc/data.conf",
        "Failed opens: 1 (not shown)",
        "Exit status: 0",
    ]


def test_trace_lines_are_capped(tmp_path, monkeypatch):
    text = "".join(
        f'1 openat(AT_FDCWD, "/etc/f{n}", O_RDONLY) = 3\n' for n in range(3)
    ) + '1 execve("/usr/bin/tool", ["tool"], 0x0 /* 1 vars */) = 0\n'
    monkeypatch.setattr(trace_module.subprocess, "run", fake_run(text))

    lines = trace_lines(tmp_path / "tool", max_items=2)

    assert "- /etc/f0" in lines
    assert "- /etc/f1" in lines
    assert "- /etc/f2" not in lines
    assert "- ... and 1 more" in lines
