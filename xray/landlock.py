"""Linux Landlock, from Python: restrict this process, then run a program.

Landlock (Linux 5.13+) lets an unprivileged process give up access to
everything except what a ruleset grants: execute, read, write per file
or directory tree, and (ABI 4+) TCP connect and bind per port. The
restriction is inherited by every child and cannot be lifted.

    python -m xray.landlock RULES.json -- /usr/bin/tool args...

applies the rules in RULES.json and then execs the program. Rules are
written by xray.enforce from a capability contract.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys

SYS_CREATE_RULESET = 444
SYS_ADD_RULE = 445
SYS_RESTRICT_SELF = 446
PR_SET_NO_NEW_PRIVS = 38
CREATE_RULESET_VERSION = 1
RULE_PATH_BENEATH = 1
RULE_NET_PORT = 2

EXECUTE = 1 << 0
WRITE_FILE = 1 << 1
READ_FILE = 1 << 2
READ_DIR = 1 << 3
REMOVE_DIR = 1 << 4
REMOVE_FILE = 1 << 5
MAKE_CHAR = 1 << 6
MAKE_DIR = 1 << 7
MAKE_REG = 1 << 8
MAKE_SOCK = 1 << 9
MAKE_FIFO = 1 << 10
MAKE_BLOCK = 1 << 11
MAKE_SYM = 1 << 12
REFER = 1 << 13      # ABI 2
TRUNCATE = 1 << 14   # ABI 3
IOCTL_DEV = 1 << 15  # ABI 5

FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV
READ = READ_FILE | READ_DIR
WRITE = (WRITE_FILE | TRUNCATE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG
         | MAKE_SOCK | MAKE_FIFO | MAKE_SYM | REFER)

NET_BIND_TCP = 1 << 0
NET_CONNECT_TCP = 1 << 1
SCOPE_ABSTRACT_UNIX = 1 << 0


class LandlockError(OSError):
    pass


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def abi_version():
    """The kernel's Landlock ABI version, or 0 when Landlock is unavailable."""

    try:
        libc = _libc()
    except OSError:
        return 0
    libc.syscall.restype = ctypes.c_long
    version = libc.syscall(ctypes.c_long(SYS_CREATE_RULESET), None, ctypes.c_size_t(0),
                           ctypes.c_uint32(CREATE_RULESET_VERSION))
    return max(int(version), 0)


def fs_rights(abi):
    rights = (1 << 13) - 1
    if abi >= 2:
        rights |= REFER
    if abi >= 3:
        rights |= TRUNCATE
    if abi >= 5:
        rights |= IOCTL_DEV
    return rights


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _NetPort(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]


def restrict(rules):
    """Apply rules to this process. rules: {"fs": [[path, rights]], "net": {...}, "scope_unix": bool}.

    Returns the list of rule paths that did not exist and were skipped.
    """

    abi = abi_version()
    if abi < 1:
        raise LandlockError("Landlock is not available on this kernel (needs Linux 5.13+ with the landlock LSM)")
    libc = _libc()
    libc.syscall.restype = ctypes.c_long
    handled_fs = fs_rights(abi)
    net = rules.get("net") or {}
    handled_net = 0
    if abi >= 4:
        if net.get("handle_connect"):
            handled_net |= NET_CONNECT_TCP
        if net.get("handle_bind"):
            handled_net |= NET_BIND_TCP
    scoped = SCOPE_ABSTRACT_UNIX if abi >= 6 and rules.get("scope_unix") else 0
    size = 24 if abi >= 6 else 16 if abi >= 4 else 8
    attr = _RulesetAttr(handled_fs, handled_net, scoped)
    ruleset = libc.syscall(ctypes.c_long(SYS_CREATE_RULESET), ctypes.byref(attr), ctypes.c_size_t(size),
                           ctypes.c_uint32(0))
    if ruleset < 0:
        raise LandlockError(ctypes.get_errno(), "landlock_create_ruleset failed")
    skipped = []
    try:
        for path, rights in rules.get("fs", []):
            try:
                fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                skipped.append(path)
                continue
            try:
                allowed = rights & handled_fs
                if not os.path.isdir(path):
                    allowed &= FILE_RIGHTS
                if not allowed:
                    continue
                beneath = _PathBeneath(allowed, fd)
                if libc.syscall(ctypes.c_long(SYS_ADD_RULE), ctypes.c_int(ruleset), ctypes.c_int(RULE_PATH_BENEATH),
                                ctypes.byref(beneath), ctypes.c_uint32(0)) < 0:
                    raise LandlockError(ctypes.get_errno(), f"landlock_add_rule failed for {path}")
            finally:
                os.close(fd)
        for key, right in (("connect", NET_CONNECT_TCP), ("bind", NET_BIND_TCP)):
            if not handled_net & right:
                continue
            for port in net.get(key, []):
                rule = _NetPort(right, int(port))
                if libc.syscall(ctypes.c_long(SYS_ADD_RULE), ctypes.c_int(ruleset), ctypes.c_int(RULE_NET_PORT),
                                ctypes.byref(rule), ctypes.c_uint32(0)) < 0:
                    raise LandlockError(ctypes.get_errno(), f"landlock_add_rule failed for port {port}")
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise LandlockError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
        if libc.syscall(ctypes.c_long(SYS_RESTRICT_SELF), ctypes.c_int(ruleset), ctypes.c_uint32(0)) < 0:
            raise LandlockError(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        os.close(ruleset)
    return skipped


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 3 or argv[1] != "--":
        print("usage: python -m xray.landlock RULES.json -- PROGRAM [ARGS...]", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as handle:
        rules = json.load(handle)
    try:
        restrict(rules)
    except LandlockError as error:
        print(f"xray: {error}", file=sys.stderr)
        return 125
    program = argv[2]
    try:
        os.execv(program, argv[2:])
    except OSError as error:
        print(f"xray: cannot run {program} under the contract: {error.strerror}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    sys.exit(main())
