"""Small persistent cache for parser output, keyed by source contents."""

import hashlib
import json
import os
import tempfile
from pathlib import Path

MAX_ENTRIES_PER_ANALYZER = 256
CACHE_SCHEMA = 1


def cache_home():
    """Return XRAY's shared cache directory, honoring standard overrides."""

    configured = os.environ.get("XRAY_CACHE")
    xdg = os.environ.get("XDG_CACHE_HOME")
    if configured:
        return Path(configured).expanduser()
    if xdg:
        return Path(xdg).expanduser() / "xray"
    return Path.home() / ".cache" / "xray"


def _root():
    return cache_home() / "analysis"


def _key(analyzer, parser_version, source):
    digest = hashlib.sha256(source).hexdigest()
    identity = f"{CACHE_SCHEMA}\0{analyzer}\0{parser_version}\0{digest}".encode()
    return hashlib.sha256(identity).hexdigest()


def get_or_compute(analyzer, parser_version, source, compute):
    """Load parser data by source hash, computing and saving it on a miss.

    Cache failures are deliberately non-fatal. Only parser output belongs here;
    import paths are resolved separately each run so installs remain visible.
    """

    key = _key(analyzer, parser_version, source)
    folder = _root() / analyzer
    cache_file = folder / f"{key}.json"

    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("schema") == CACHE_SCHEMA:
            return data["result"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        pass

    result = compute()

    try:
        folder.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=folder, prefix=".cache-",
            suffix=".tmp", delete=False,
        ) as temp:
            json.dump({"schema": CACHE_SCHEMA, "result": result}, temp)
            temp_path = Path(temp.name)

        os.replace(temp_path, cache_file)
        _prune(folder)
    except OSError:
        try:
            temp_path.unlink(missing_ok=True)
        except (OSError, UnboundLocalError):
            pass

    return result


def _prune(folder):
    entries = sorted(
        folder.glob("*.json"), key=lambda path: path.stat().st_mtime_ns
    )

    for stale in entries[:-MAX_ENTRIES_PER_ANALYZER]:
        try:
            stale.unlink()
        except OSError:
            continue
