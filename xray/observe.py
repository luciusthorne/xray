"""Observe what a real run does, as capabilities: exec, read, write, net.

The program runs under ``strace -f`` with the file, socket and process
calls traced. Relative paths are resolved against each process's
working directory, followed through chdir and inherited across fork.
Only calls that succeeded count, except connect, where an attempt (a
non-blocking EINPROGRESS too) is what matters.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import AnalysisError

_CALLS = (
    "execve,execveat,open,openat,openat2,creat,mkdir,mkdirat,unlink,unlinkat,rename,renameat,renameat2,"
    "rmdir,symlink,symlinkat,link,linkat,truncate,chdir,fchdir,socket,connect,bind,clone,clone3,fork,vfork"
)
_LINE = re.compile(r"^(?P<pid>\d+)\s+(?P<call>\w+)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|\?)(?P<rest>.*)$")
_UNFINISHED = re.compile(r"^(?P<pid>\d+)\s+(?P<head>.*) <unfinished \.\.\.>$")
_RESUMED = re.compile(r"^(?P<pid>\d+)\s+<\.\.\. (?P<call>\w+) resumed>(?P<tail>.*)$")
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
_FAMILY = re.compile(r"sa_family=(AF_\w+)")
_UNIX_PATH = re.compile(r'sun_path=(@?)"((?:[^"\\]|\\.)*)"')


@dataclass
class Observed:
    """Capabilities a traced run used. Paths are absolute and unique, in first-use order."""

    exec: list = field(default_factory=list)
    read: list = field(default_factory=list)
    write: list = field(default_factory=list)
    net: list = field(default_factory=list)  # (kind, protocol, port-or-path)
    status: int | None = None
    timed_out: bool = False

    def add(self, section, value):
        bucket = getattr(self, section)
        if value not in bucket:
            bucket.append(value)


def _unescape(text):
    return text.encode("latin-1", "backslashreplace").decode("unicode_escape", "replace")


def parse_capabilities(text, cwd):
    """Return Observed from strace -f output (one call per line, pid first)."""

    observed = Observed()
    cwds = {}
    sockets = {}  # (pid, fd) -> protocol
    pending = {}

    def cwd_of(pid):
        return cwds.get(pid, cwd)

    def absolute(pid, path, dirfd_arg=None):
        if path.startswith("/"):
            return os.path.normpath(path)
        base = cwd_of(pid)
        if dirfd_arg and "<" in dirfd_arg and dirfd_arg.endswith(">"):
            base = dirfd_arg[dirfd_arg.index("<") + 1:-1]
        return os.path.normpath(os.path.join(base, path))

    root_pid = None
    for raw in text.splitlines():
        unfinished = _UNFINISHED.match(raw)
        if unfinished:
            pending[unfinished.group("pid")] = unfinished.group("head")
            continue
        resumed = _RESUMED.match(raw)
        if resumed:
            head = pending.pop(resumed.group("pid"), None)
            if head is None:
                continue
            raw = f"{resumed.group('pid')} {head}{resumed.group('tail')}"
        match = _LINE.match(raw)
        if not match:
            continue
        pid, call, args, ret = match.group("pid"), match.group("call"), match.group("args"), match.group("ret")
        if root_pid is None:
            root_pid = pid
        code = int(ret) if ret != "?" else -1
        strings = [_unescape(item) for item in _STRING.findall(args)]
        first_arg = args.split(",", 1)[0].strip()

        if call in ("clone", "clone3", "fork", "vfork"):
            if code > 0:
                cwds[str(code)] = cwd_of(pid)
            continue
        if call == "socket" and code >= 0:
            sockets[(pid, str(code))] = "udp" if "SOCK_DGRAM" in args else "tcp" if "SOCK_STREAM" in args else "other"
            continue
        if call in ("connect", "bind"):
            if code < 0 and "EINPROGRESS" not in match.group("rest"):
                continue
            family = _FAMILY.search(args)
            family = family.group(1) if family else ""
            if family == "AF_UNIX":
                unix = _UNIX_PATH.search(args)
                where = (("@" if unix.group(1) else "") + _unescape(unix.group(2))) if unix else ""
                observed.add("net", ("unix", "unix", where))
            elif family in ("AF_INET", "AF_INET6"):
                port = _PORT.search(args)
                fd = first_arg.split("<", 1)[0]
                protocol = sockets.get((pid, fd), "tcp")
                observed.add("net", (call, protocol, int(port.group(1)) if port else 0))
            continue
        if code < 0:
            continue
        if call == "chdir" and strings:
            cwds[pid] = absolute(pid, strings[0])
            continue
        if call == "fchdir":
            continue
        if not strings:
            continue
        if call in ("execve", "execveat"):
            observed.add("exec", absolute(pid, strings[0]))
            continue
        if call in ("open", "openat", "openat2", "creat"):
            dirfd = first_arg if call in ("openat", "openat2") else None
            path = absolute(pid, strings[0], dirfd)
            if call == "creat" or any(flag in args for flag in _WRITE_FLAGS):
                observed.add("write", path)
            else:
                observed.add("read", path)
            continue
        # every remaining call changes the file system
        for path in strings[:2] if call in ("rename", "renameat", "renameat2", "link", "linkat") else strings[-1:]:
            observed.add("write", absolute(pid, path))
    return observed


def strace_path():
    return os.environ.get("XRAY_STRACE") or shutil.which("strace")


def observe_run(argv, timeout=30, cwd=None, stdin=None):
    """Run argv under strace and return Observed. This really runs the program."""

    strace = strace_path()
    if strace is None:
        raise AnalysisError("strace not found: install the strace package (or set XRAY_STRACE)")
    cwd = str(Path(cwd or os.getcwd()).resolve())
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder) / "trace.txt"
        command = [strace, "-f", "-qq", "-s", "4096", "-y", "-e", f"trace={_CALLS}", "-o", str(out), "--", *argv]
        status, timed_out = None, False
        try:
            completed = subprocess.run(
                command, cwd=cwd, stdin=stdin if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=False,
            )
            status = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as error:
            raise AnalysisError(f"Unable to run strace: {error}") from error
        text = out.read_text(encoding="utf-8", errors="replace") if out.exists() else ""
    if not text.strip():
        raise AnalysisError("strace produced no trace: the command may not be runnable here")
    observed = parse_capabilities(text, cwd)
    observed.status, observed.timed_out = status, timed_out
    return observed
