"""System-call denials for capability contracts, enforced with seccomp.

A contract's [syscalls] section lists dangerous system calls the program shows
no sign of using (`deny NAME`). Under `xray contract enforce` they fail with
EPERM through a seccomp filter installed just before the program starts, after
Landlock; `xray contract systemd` turns them into SystemCallFilter=.

Generation is evidence-based: a call stays allowed when the program or any
library it loads imports the C library function of that name, or a traced run
used it. A program that calls syscall() directly can reach any number; the
contract says so, and a traced check or minimize run is the way to confirm.
"""

import ctypes
import os
import platform
import struct

# Groups of calls that ordinary programs never need, with the reason shown in contracts.
GROUPS = {
    "debugging other processes": ("ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd"),
    "kernel modules and kexec": ("init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load"),
    "mounts and namespaces": ("mount", "umount2", "pivot_root", "chroot", "setns", "unshare", "move_mount",
                              "open_tree", "fsopen", "fsconfig", "fsmount", "mount_setattr"),
    "system state": ("reboot", "swapon", "swapoff", "settimeofday", "clock_settime", "clock_adjtime",
                     "adjtimex", "acct", "quotactl"),
    "eBPF, perf and userfaultfd": ("bpf", "perf_event_open", "userfaultfd"),
    "kernel keyrings": ("keyctl", "add_key", "request_key"),
    "raw I/O ports and file handles": ("iopl", "ioperm", "open_by_handle_at", "name_to_handle_at"),
}
REASON = {name: group for group, names in GROUPS.items() for name in names}

# C library functions that make each call; importing one means the program may need it.
WRAPPERS = {
    "umount2": ("umount2", "umount"),
    "adjtimex": ("adjtimex", "ntp_adjtime", "__adjtimex"),
    "clock_adjtime": ("clock_adjtime",),
}

# x86-64 numbers (asm/unistd_64.h; tests/test_seccomp.py checks them against the header when present).
X86_64 = {
    "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "pidfd_getfd": 438,
    "init_module": 175, "finit_module": 313, "delete_module": 176, "kexec_load": 246, "kexec_file_load": 320,
    "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161, "setns": 308, "unshare": 272,
    "move_mount": 429, "open_tree": 428, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "mount_setattr": 442,
    "reboot": 169, "swapon": 167, "swapoff": 168, "settimeofday": 164, "clock_settime": 227,
    "clock_adjtime": 305, "adjtimex": 159, "acct": 163, "quotactl": 179,
    "bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
    "keyctl": 250, "add_key": 248, "request_key": 249,
    "iopl": 172, "ioperm": 173, "open_by_handle_at": 304, "name_to_handle_at": 303,
}
KNOWN = tuple(X86_64)

AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL_BIT = 0x40000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
_LD_W_ABS, _JEQ_K, _JSET_K, _RET_K = 0x20, 0x15, 0x45, 0x06


class SeccompError(OSError):
    pass


def supported():
    """True where XRAY can build a filter (x86-64 Linux)."""

    return platform.machine() in ("x86_64", "AMD64")


def denials(imports, observed=()):
    """[(name, reason)] to deny given the C functions the program and its libraries import.

    imports: every imported symbol name across the program and the libraries it
    loads; observed: system call names a traced run used.
    """

    imports, observed = set(imports), set(observed)
    out = []
    for name in KNOWN:
        if name in observed or any(wrapper in imports for wrapper in WRAPPERS.get(name, (name,))):
            continue
        out.append((name, REASON[name]))
    return out


def program(names):
    """The BPF program (bytes) that returns EPERM for names and allows the rest on x86-64.

    Other architectures (32-bit int 0x80 calls) and the x32 ABI get EPERM for
    everything, so a denied call cannot be reached under another number.
    """

    numbers = sorted({X86_64[name] for name in names})
    eperm = SECCOMP_RET_ERRNO | 1
    code = [
        (_LD_W_ABS, 0, 0, 4),                    # arch
        (_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        (_RET_K, 0, 0, eperm),                   # foreign architecture
        (_LD_W_ABS, 0, 0, 0),                    # system call number
        (_JSET_K, 0, 1, X32_SYSCALL_BIT),
        (_RET_K, 0, 0, eperm),                   # x32 ABI
    ]
    for index, number in enumerate(numbers):
        remaining = len(numbers) - index - 1
        code.append((_JEQ_K, remaining + 1, 0, number))  # jump to the EPERM return at the end
    code.append((_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    code.append((_RET_K, 0, 0, eperm))
    return b"".join(struct.pack("<HBBI", *instruction) for instruction in code), len(code)


class _Fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install(names):
    """Install the filter in this process (inherited across exec). Needs no privileges."""

    if not names:
        return
    if not supported():
        raise SeccompError(f"seccomp denials are built for x86-64 only, not {platform.machine()}")
    unknown = [name for name in names if name not in X86_64]
    if unknown:
        raise SeccompError(f"unknown system calls: {', '.join(unknown)}")
    code, count = program(names)
    buffer = ctypes.create_string_buffer(code, len(code))
    prog = _Fprog(count, ctypes.cast(buffer, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SeccompError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        raise SeccompError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
