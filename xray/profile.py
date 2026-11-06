"""Capability profiles: what one file is able to do, read from its contents alone.

A profile does not depend on the machine it is computed on, so profiles
of two package versions, or of the same package on two machines, can be
compared. For ELF files it lists the libraries named in DT_NEEDED, the
search paths, and the imported symbols grouped into capability classes
(network, starting programs, loading code at run time, changing
identity, inspecting other processes, kernel administration), plus
the IFUNC resolvers and constructors that run before main — the hooks
the 2024 xz backdoor used. For scripts it lists the commands they run
and what they load.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

from .entrypoints import command_kind

PROFILE_VERSION = 1

CLASSES = {
    "net": ("socket", "connect", "bind", "listen", "accept", "accept4", "getaddrinfo", "gethostbyname",
            "gethostbyname2", "gethostbyname_r", "sendto", "recvfrom", "sendmsg", "recvmsg"),
    "exec": ("execve", "execv", "execvp", "execvpe", "execl", "execlp", "execle", "fexecve", "execveat",
             "posix_spawn", "posix_spawnp"),
    "shell": ("system", "popen"),
    "dynload": ("dlopen", "dlmopen", "dlsym", "dlvsym"),
    "identity": ("setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid", "setresuid", "setresgid",
                 "setgroups", "initgroups", "capset", "cap_set_proc"),
    "ptrace": ("ptrace", "process_vm_readv", "process_vm_writev"),
    "kernel": ("init_module", "finit_module", "delete_module", "kexec_load", "bpf", "mount", "umount",
               "umount2", "pivot_root", "chroot", "unshare", "setns", "reboot", "swapon", "swapoff"),
}
_CLASS_OF = {symbol: name for name, symbols in CLASSES.items() for symbol in symbols}

# Commands whose use in a script gives the script a capability class.
COMMAND_CLASSES = {
    "net": ("curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "telnet", "ftp"),
    "identity": ("sudo", "doas", "su", "pkexec", "runuser", "setpriv", "chown", "chmod", "setcap"),
    "kernel": ("modprobe", "insmod", "rmmod", "mount", "umount", "chroot", "unshare", "nsenter", "sysctl",
               "iptables", "nft", "ip", "systemctl"),
    "ptrace": ("gdb", "strace", "ltrace"),
}
PYTHON_CLASSES = {
    "net": ("socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp", "ftplib", "smtplib", "paramiko"),
    "exec": ("subprocess", "pty", "multiprocessing"),
    "dynload": ("ctypes", "cffi", "importlib"),
}

# The dynamic loader and the C library it ships with: they link each other and use IFUNCs by design.
LOADER_FAMILY = re.compile(r"^(ld-linux[^/]*|ld64\.so\.\d+|ld-musl[^/]*|libc\.so\.\d+|libm\.so\.\d+|libmvec\.so\.\d+)$")
LOADER_NAMES = re.compile(r"^(ld-linux[^/]*|ld64\.so\.\d+|ld-musl[^/]*)$")


def loader_hook(data, name):
    """True for a library outside the loader's own family that links the dynamic loader and has IFUNC resolvers.

    Its IFUNC resolvers run inside the loader while it relocates the
    program, before main and before any constructor: the hook the 2024 xz
    backdoor used. On the 500 most popular Arch packages and every
    library of a full desktop install, only glibc itself does this.
    """

    return (
        data.get("kind") == "elf"
        and bool(data.get("soname") or ".so" in name)
        and not LOADER_FAMILY.match(Path(name).name)
        and not LOADER_FAMILY.match(data.get("soname") or "")
        and any(LOADER_NAMES.match(item) for item in data.get("needed") or ())
        and (data.get("ifuncs") or 0) > 0
    )


_SYMBOL = re.compile(r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+(\w+)\s+(\w+)\s+\w+\s+(\S+)\s+(\S+)")
_NEEDED = re.compile(r"\(NEEDED\)\s+Shared library: \[(.+?)\]")
_SONAME = re.compile(r"\(SONAME\)\s+Library soname: \[(.+?)\]")
_RPATH = re.compile(r"\((RPATH|RUNPATH)\)\s+Library r(?:un)?path: \[(.*?)\]")
_INIT = re.compile(r"\((INIT_ARRAYSZ|PREINIT_ARRAYSZ)\)\s+(\d+) \(bytes\)")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _readelf(path):
    env = dict(os.environ, LC_ALL="C")
    try:
        done = subprocess.run(["readelf", "-d", "--dyn-syms", "-W", str(path)], capture_output=True, text=True,
                              errors="replace", env=env, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return done.stdout


def _elf_profile(path):
    text = _readelf(path)
    imports, ifuncs, exports = set(), 0, 0
    for line in text.splitlines():
        match = _SYMBOL.match(line)
        if not match:
            continue
        kind, bind, index, name = match.groups()
        name = name.split("@", 1)[0]
        if index == "UND":
            if name:
                imports.add(name)
        elif bind in ("GLOBAL", "WEAK"):
            exports += 1
            if kind == "IFUNC":
                ifuncs += 1
    classes = {}
    for name in sorted(imports):
        found = _CLASS_OF.get(name)
        if found:
            classes.setdefault(found, []).append(name)
    paths = {kind.lower(): value for kind, value in _RPATH.findall(text)}
    constructors = sum(int(size) // 8 for _, size in _INIT.findall(text))
    soname = _SONAME.search(text)
    return {
        "needed": sorted(set(_NEEDED.findall(text))),
        "soname": soname.group(1) if soname else None,
        "rpath": paths.get("rpath"),
        "runpath": paths.get("runpath"),
        "classes": classes,
        "imports": len(imports),
        "exports": exports,
        "ifuncs": ifuncs,
        "constructors": constructors,
    }


def _shell_profile(path):
    from .shellscan import shell_facts

    facts = shell_facts(path)
    classes = {}
    for name in facts.commands:
        base = Path(name).name
        for cls, names in COMMAND_CLASSES.items():
            if base in names:
                classes.setdefault(cls, []).append(base)
    return {
        "commands": sorted({Path(name).name for name in facts.commands}),
        "sources": sorted(facts.sources),
        "dynamic": len(facts.dynamic),
        "changes_path": bool(facts.path_lines),
        "classes": {cls: sorted(set(names)) for cls, names in classes.items()},
    }


def _python_profile(path):
    from .pyexec import python_exec

    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return {"imports": [], "commands": [], "classes": {}, "unparsed": True}
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            modules.add(node.module.split(".")[0])
    classes = {}
    for cls, names in PYTHON_CLASSES.items():
        hit = sorted(modules & set(names))
        if hit:
            classes[cls] = hit
    commands = sorted({Path(name).name for name in python_exec(path).commands})
    for name in commands:
        for cls, names in COMMAND_CLASSES.items():
            if name in names:
                classes.setdefault(cls, [])
                if name not in classes[cls]:
                    classes[cls].append(name)
    return {"imports": sorted(modules), "commands": commands, "classes": classes}


def _interpreter(path):
    try:
        with open(path, "rb") as handle:
            first = handle.readline(256)
    except OSError:
        return None
    if first.startswith(b"#!"):
        return first[2:].decode("utf-8", "replace").strip()
    return None


def profile(path):
    """The capability profile of one file, as plain data. Nothing is run."""

    path = Path(path).resolve()
    info = path.stat()
    data = {
        "version": PROFILE_VERSION,
        "kind": command_kind(path),
        "sha256": sha256(path),
        "size": info.st_size,
        "setuid": bool(info.st_mode & stat.S_ISUID),
        "setgid": bool(info.st_mode & stat.S_ISGID),
        "executable": bool(info.st_mode & 0o111),
    }
    kind = data["kind"]
    if kind == "elf":
        data.update(_elf_profile(path))
    elif kind == "shell":
        data["interpreter"] = _interpreter(path)
        data.update(_shell_profile(path))
    elif kind == "python":
        data["interpreter"] = _interpreter(path)
        data.update(_python_profile(path))
    else:
        data["interpreter"] = _interpreter(path)
        data["classes"] = {}
    return data


_SCRIPT_SUFFIXES = (".py", ".sh", ".bash", ".pl", ".pm", ".rb", ".js", ".mjs", ".cjs", ".lua")


def interesting(path):
    """Files worth profiling: ELF files, executable scripts, and script-language modules."""

    try:
        if not path.is_file() or path.is_symlink():
            return False
    except OSError:
        return False
    kind = command_kind(path)
    if kind == "elf":
        return True
    if kind == "unknown":
        return False
    return os.access(path, os.X_OK) or path.suffix in _SCRIPT_SUFFIXES
