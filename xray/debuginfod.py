"""Optional source lookup through elfutils debuginfod.

The client library uses the user's DEBUGINFOD_URLS configuration and cache.
No package build scripts are executed. Missing libraries, symbols, or source
files are reported as an unavailable lookup so callers can fall back safely.
"""

import ctypes
import ctypes.util
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

from xray.minidebug import parse_function_table

_BUILD_ID = re.compile(r"Build ID: ([0-9a-fA-F]+)")
_LOCATION = re.compile(r"^(.*?):(\d+)(?::\d+)?$")
_ENV_LOCK = threading.Lock()


def configured():
    """Whether the user configured any debuginfod servers."""
    return bool(os.environ.get("DEBUGINFOD_URLS", "").strip())


def _library():
    name = ctypes.util.find_library("debuginfod")
    if not name:
        return None
    try:
        lib = ctypes.CDLL(name)
    except OSError:
        return None
    lib.debuginfod_begin.restype = ctypes.c_void_p
    lib.debuginfod_end.argtypes = [ctypes.c_void_p]
    lib.debuginfod_find_debuginfo.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.debuginfod_find_debuginfo.restype = ctypes.c_int
    lib.debuginfod_find_source.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.debuginfod_find_source.restype = ctypes.c_int
    return lib


def _build_id(path):
    try:
        result = subprocess.run(
            ["readelf", "-n", str(path)],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = _BUILD_ID.search(result.stdout)
    return match.group(1).lower() if result.returncode == 0 and match else None


def _begin(lib):
    # Keep accidental network stalls bounded while preserving explicit user
    # settings. elfutils snapshots these settings when its client is created.
    with _ENV_LOCK:
        defaults = {
            "DEBUGINFOD_TIMEOUT": "5",
            "DEBUGINFOD_MAXTIME": "20",
            "DEBUGINFOD_MAXSIZE": str(128 * 1024 * 1024),
        }
        previous = {key: os.environ.get(key) for key in defaults}
        for key, value in defaults.items():
            os.environ.setdefault(key, value)
        try:
            return lib.debuginfod_begin()
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def _lookup(lib, client, build_id, filename=None):
    output_path = ctypes.c_void_p()
    if filename is None:
        fd = lib.debuginfod_find_debuginfo(
            client, build_id.encode("ascii"), 0, ctypes.byref(output_path)
        )
    else:
        fd = lib.debuginfod_find_source(
            client,
            build_id.encode("ascii"),
            0,
            os.fsencode(filename),
            ctypes.byref(output_path),
        )
    if fd < 0:
        return None
    try:
        cached_path = Path(ctypes.string_at(output_path).decode(errors="replace"))
        return cached_path
    finally:
        os.close(fd)
        if output_path:
            ctypes.CDLL(None).free(output_path)


def _debug_function_table(lib, client, build_id):
    debug_file = _lookup(lib, client, build_id)
    if debug_file is None:
        return None, ()
    try:
        result = subprocess.run(
            ["readelf", "-sW", str(debug_file)],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return debug_file, ()
    table = parse_function_table(result.stdout) if result.returncode == 0 else ()
    return debug_file, table


def function_table(binary):
    """Return (address, size, name) rows from the binary's debuginfod debug file.

    The debug file comes from the same build (same build ID), so its
    addresses match the installed binary."""
    if not configured():
        return ()
    lib = _library()
    if lib is None:
        return ()
    build_id = _build_id(binary)
    if build_id is None:
        return ()
    client = _begin(lib)
    if not client:
        return ()
    try:
        return tuple(_debug_function_table(lib, client, build_id)[1])
    finally:
        lib.debuginfod_end(client)


def function_names(binary):
    """Return function names from configured debuginfod data, if available."""
    if not configured():
        return ()
    lib = _library()
    if lib is None:
        return ()
    build_id = _build_id(binary)
    if build_id is None:
        return ()
    client = _begin(lib)
    if not client:
        return ()
    try:
        _debug_file, table = _debug_function_table(lib, client, build_id)
        return tuple(sorted({entry[2] for entry in table}))
    finally:
        lib.debuginfod_end(client)


def function_source(binary, name):
    """Return (DWARF source path, cached source path, line) for a function."""
    if not configured():
        return None
    lib = _library()
    if lib is None:
        return None
    build_id = _build_id(binary)
    if build_id is None:
        return None

    client = _begin(lib)
    if not client:
        return None
    try:
        debug_file, symbols = _debug_function_table(lib, client, build_id)
        if debug_file is None:
            return None
        matches = [entry for entry in symbols if entry[2] == name]
        if not matches:
            plain = re.sub(r"(?:\.(?:isra|constprop|part|cold|lto_priv)(?:\.\d+)?)+$", "", name)
            matches = [entry for entry in symbols if entry[2] == plain]
        if not matches:
            return None
        address, _size, _symbol_name = matches[0]

        tool = shutil.which("eu-addr2line") or shutil.which("addr2line")
        if tool is None:
            return None
        try:
            location = subprocess.run(
                [tool, "-f", "-C", "-e", str(debug_file), hex(address)],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        rows = location.stdout.splitlines()
        if location.returncode != 0 or len(rows) < 2:
            return None
        match = _LOCATION.match(rows[1])
        if not match or match.group(1) in {"??", ""}:
            return None
        source_name, line = match.group(1), int(match.group(2))
        cached_source = _lookup(lib, client, build_id, source_name)
        if cached_source is None or not cached_source.is_file():
            return None
        return Path(source_name), cached_source, line
    finally:
        lib.debuginfod_end(client)
