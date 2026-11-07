"""Run a program held to its capability contract.

Two layers, both unprivileged:

- Landlock (always): the process may execute only [exec] files, read
  only [exec], [load], [read], [write] and baseline paths, change only
  [write] paths, and (kernel ABI 4+) connect or bind only the TCP ports
  [net] lists. Abstract unix sockets are cut off (ABI 6+) unless [net]
  allows unix.
- bubblewrap (when [net] is none): a private network namespace, so no
  network at all, UDP included.

Landlock grants are per file or per directory tree. A read entry such as
/etc/tool/*.conf is enforced as the files that match when the program
starts; a write entry with a glob is enforced on its directory, since the
files it creates do not exist yet. ``xray contract
check --trace`` reports accesses at the exact granularity of the contract.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import landlock as ll
from .contract import BASELINE_DEVICES, BASELINE_READ, expand_home
from .errors import CLIError


def _root_of(value, home=None):
    """The file or directory a contract path entry is enforced on."""

    value = expand_home(value, home)
    if value.endswith("/**"):
        return value[:-3] or "/"
    if any(ch in Path(value).name for ch in "*?["):
        return str(Path(value).parent)
    return value


def _roots_for_reading(value, home=None):
    """What a read, exec or load entry is enforced on. A glob in the last component (/etc/tool/*.conf)
    is expanded to the files that match now, instead of granting the whole directory."""

    expanded = expand_home(value, home)
    if not expanded.endswith("/**") and any(ch in Path(expanded).name for ch in "*?["):
        return sorted(glob.glob(expanded))
    return [_root_of(value, home)]


def landlock_rules(contract, home=None, extra_read=(), extra_write=()):
    rights = {}

    def grant(path, bits):
        rights[path] = rights.get(path, 0) | bits

    for value in contract.values("exec"):
        for root in _roots_for_reading(value, home):
            grant(root, ll.EXECUTE | ll.READ)
    for value in contract.values("load"):
        for root in _roots_for_reading(value, home):
            grant(root, ll.READ | (ll.EXECUTE if Path(root).name.startswith("ld-") else 0))
    for value in [*contract.values("read"), *extra_read]:
        for root in _roots_for_reading(value, home):
            grant(root, ll.READ)
    for value in [*contract.values("write"), *extra_write]:
        root = _root_of(value, home)
        if os.path.isdir(root) or value.endswith(("/**", "/*")):
            grant(root, ll.READ | ll.WRITE)
        elif os.path.exists(root):
            grant(root, ll.READ_FILE | ll.WRITE_FILE | ll.TRUNCATE)
        else:
            grant(str(Path(root).parent), ll.READ | ll.WRITE)  # the file is created there
    for value in BASELINE_READ:
        grant(_root_of(value), ll.READ)
    for value in BASELINE_DEVICES:
        grant(_root_of(value), ll.READ | ll.WRITE_FILE | ll.IOCTL_DEV)

    net = contract.values("net")
    connect = [int(v.split()[2]) for v in net if v.startswith("connect tcp ") and v.split()[2] != "*"]
    bind = [int(v.split()[2]) for v in net if v.startswith("bind tcp ") and v.split()[2] != "*"]
    rules = {
        "fs": sorted([path, bits] for path, bits in rights.items()),
        "net": {
            "handle_connect": "any" not in net and "connect tcp *" not in net,
            "handle_bind": "any" not in net and "bind tcp *" not in net,
            "connect": connect,
            "bind": bind,
        },
        "scope_unix": "any" not in net and "unix" not in net,
        "seccomp_deny": list(contract.values("syscalls")),
    }
    return rules


def enforce_command(contract, args, rules_path, python=None):
    """The argv that runs the program under the contract."""

    program = contract.program
    inner = [python or sys.executable, "-m", "xray.landlock", rules_path, "--", program, *args]
    if contract.values("net"):
        return inner
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise CLIError("the contract allows no network: install bubblewrap (bwrap) to enforce that")
    return [bwrap, "--dev-bind", "/", "/", "--unshare-net", "--die-with-parent", "--", *inner]


def run_enforced(contract, args, extra_read=(), extra_write=(), capture=False, timeout=None, stdin=None):
    """Run the program under the contract; return the CompletedProcess."""

    if ll.abi_version() < 1:
        raise CLIError("Landlock is not available on this kernel: contracts cannot be enforced here")
    if not Path(contract.program).exists():
        raise CLIError(f"the contract's program does not exist: {contract.program}")
    rules = landlock_rules(contract, extra_read=extra_read, extra_write=extra_write)
    with tempfile.TemporaryDirectory(prefix="xray-contract-") as folder:
        rules_path = os.path.join(folder, "rules.json")
        with open(rules_path, "w", encoding="utf-8") as handle:
            json.dump(rules, handle)
        command = enforce_command(contract, args, rules_path)
        env = dict(os.environ)
        package_root = str(Path(__file__).resolve().parent.parent)
        env["PYTHONPATH"] = package_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        return subprocess.run(
            command, env=env, check=False, timeout=timeout,
            capture_output=capture, stdin=stdin,
        )
