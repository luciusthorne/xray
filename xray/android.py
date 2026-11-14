"""Android (Termux) facts XRAY needs to read programs the way bionic loads them.

Termux is a Linux userland inside an Android app: its programs live under
``$PREFIX`` (``/data/data/com.termux/files/usr``), are linked against
bionic, and are loaded by ``/system/bin/linker64``. Bionic's loader has no
ldconfig cache; it searches LD_LIBRARY_PATH, the object's DT_RUNPATH and
then the system library directories. Termux builds every program with
``DT_RUNPATH=$PREFIX/lib``.
"""

import os
import shutil
import sys
from functools import lru_cache
from pathlib import Path

TERMUX_PREFIX = "/data/data/com.termux/files/usr"


@lru_cache(maxsize=1)
def is_android():
    return sys.platform == "android" or (
        Path("/system/bin/linker64").exists() and Path("/system/build.prop").exists()
    ) or (Path("/system/bin/linker64").exists() and "ANDROID_ROOT" in os.environ)


def prefix():
    """Termux's $PREFIX, or None outside Termux."""

    value = os.environ.get("PREFIX", "")
    if "com.termux" in value and Path(value).is_dir():
        return value
    return TERMUX_PREFIX if Path(TERMUX_PREFIX).is_dir() else None


def system_library_dirs(elf_class=64):
    """Bionic's default search directories, in order (only those that exist)."""

    suffix = "lib64" if elf_class == 64 else "lib"
    candidates = (
        f"/apex/com.android.runtime/{suffix}/bionic",
        f"/system/{suffix}",
        f"/apex/com.android.art/{suffix}",
        f"/vendor/{suffix}",
        f"/odm/{suffix}",
        f"/product/{suffix}",
        f"/system_ext/{suffix}",
    )
    return tuple(directory for directory in candidates if Path(directory).is_dir())


def library_dirs(elf_class=64):
    """Directories to look in for a library by name: Termux's lib, then the system's."""

    termux = prefix()
    return ((f"{termux}/lib",) if termux else ()) + system_library_dirs(elf_class)


def binutil(name):
    """The program to run for a binutils tool name.

    The plain name when it is installed, else GNU's ``g``-prefixed copy
    (Termux's ``binutils`` package installs ``greadelf``, ``gobjdump``, ...;
    its plain names come from ``llvm``). For ``objdump`` GNU's is preferred,
    because XRAY reads GNU objdump's disassembly.
    """

    plain = shutil.which(name)
    if name == "objdump" and plain and "llvm" in Path(plain).resolve().name:
        return shutil.which("g" + name) or name
    if plain:
        return name
    return shutil.which("g" + name) or name


gnu_tool = binutil


def termux_exec_path(program):
    """Where termux-exec runs a shebang's /bin/X or /usr/bin/X ($PREFIX/bin/X), or None.

    Android has no /bin or /usr/bin; Termux preloads termux-exec, which
    rewrites those interpreter paths to $PREFIX/bin when a script starts.
    """

    if not is_android():
        return None
    termux = prefix()
    if termux is None:
        return None
    for root in ("/usr/bin/", "/bin/", "/usr/local/bin/"):
        if program.startswith(root):
            candidate = Path(termux) / "bin" / program[len(root):]
            return candidate if candidate.is_file() else None
    return None
