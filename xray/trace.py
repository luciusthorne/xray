import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from xray.errors import AnalysisError

_EXEC = re.compile(r'^(?:\d+\s+)?execve\("((?:[^"\\]|\\.)*)".*\)\s+=\s+(-?\d+)\b')
_OPEN = re.compile(
    r'^(?:\d+\s+)?openat\([^,]+,\s+"((?:[^"\\]|\\.)*)".*\)\s+=\s+(-?\d+)\b'
)

NOISE = ("/proc/", "/sys/", "/dev/", "/etc/ld.so.cache")


@dataclass(frozen=True)
class TraceResult:
    """What a traced command executed and opened.

    executed and opened hold each path once, in the order first seen.
    failed counts open calls that failed. status is the exit status
    of the command, or None when it was stopped after a timeout.
    """

    executed: tuple = ()
    opened: tuple = ()
    failed: int = 0
    status: int | None = None
    timed_out: bool = False


def parse_trace(text):
    """Return a TraceResult from strace -f output for execve and openat.

    Calls that were still unfinished when the line was written are
    not counted. Paths under /proc, /sys and /dev, and the loader
    cache, are left out of opened.
    """

    executed = []
    opened = []
    failed = 0

    for line in text.splitlines():
        match = _EXEC.match(line)

        if match:
            name = match.group(1)

            if int(match.group(2)) >= 0 and name not in executed:
                executed.append(name)

            continue

        match = _OPEN.match(line)

        if match:
            name = match.group(1)

            if int(match.group(2)) < 0:
                failed += 1
            elif not name.startswith(NOISE) and name not in opened:
                opened.append(name)

    return TraceResult(tuple(executed), tuple(opened), failed)


def run_trace(path, args=(), timeout=10):
    """Run a command under strace and return what it executed and opened.

    This really runs the command. Its own output is discarded, and it
    is stopped after timeout seconds. A missing strace, or a trace
    that holds nothing, raises AnalysisError.
    """

    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder) / "trace.txt"
        command = [
            "strace",
            "-f",
            "-e",
            "trace=execve,openat",
            "-o",
            str(out),
            "--",
            str(path),
            *args,
        ]
        status = None
        timed_out = False

        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
            status = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        except FileNotFoundError as error:
            raise AnalysisError(
                "strace not found: install the strace package"
            ) from error
        except OSError as error:
            raise AnalysisError(f"Unable to run strace: {error}") from error

        text = (
            out.read_text(encoding="utf-8", errors="replace")
            if out.exists()
            else ""
        )

    if not text.strip() and not timed_out:
        raise AnalysisError(
            "strace produced no trace: the command may not be runnable here"
        )

    parsed = parse_trace(text)

    return TraceResult(
        parsed.executed, parsed.opened, parsed.failed, status, timed_out
    )


def _limited(items, max_items):
    if not items:
        return ["none"]

    lines = [f"- {item}" for item in items[:max_items]]
    hidden = len(items) - max_items

    if hidden > 0:
        lines.append(f"- ... and {hidden} more")

    return lines


def trace_lines(path, args=(), timeout=10, max_items=50):
    """Return the report lines for a traced run of a command."""

    result = run_trace(path, args, timeout)
    lines = [
        "Executed:",
        *_limited(result.executed, max_items),
        "Opened:",
        *_limited(result.opened, max_items),
    ]

    if result.failed:
        lines.append(f"Failed opens: {result.failed} (not shown)")

    if result.timed_out:
        lines.append(
            f"Timed out after {timeout} seconds: the command was stopped"
        )
    else:
        lines.append(f"Exit status: {result.status}")

    return lines
