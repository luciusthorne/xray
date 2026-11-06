"""A live capability feed for Arch Linux: every package update, profiled as it lands.

``xray feed update`` downloads the repository databases from the
configured mirror and finds the packages whose version changed since
the last run. Each new archive is checked against the packager's
signature (embedded in the database, verified with the pacman keyring)
and its SHA-256, profiled into the capability log, and compared with the version before
it (taken from the log, or fetched from archive.archlinux.org). Every
update becomes one feed entry: what the new version gained, with the
strong gains (call classes, loader hooks, IFUNC resolvers,
constructors, setuid) marked. The first run only records the current
versions, so the feed starts from now.

``xray feed report`` prints the feed as text or as a self-contained
HTML page, and ``xray feed timer`` writes a systemd user timer that
runs the update every hour.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import html
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from . import caplog
from .crossbuild import STRONG_FIELDS

USER_AGENT = "xray-feed/1.1 (+https://github.com/luciusthorne/xray)"
ARCHIVE = "https://archive.archlinux.org/packages"
DEFAULT_REPOS = ("core", "extra")


class FeedError(RuntimeError):
    pass


def data_dir():
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "xray"


def default_paths():
    folder = data_dir()
    return {"log": folder / "arch-capability-log.jsonl", "state": folder / "feed-state.json",
            "feed": folder / "feed.jsonl"}


def mirror(mirrorlist="/etc/pacman.d/mirrorlist"):
    for line in Path(mirrorlist).read_text().splitlines():
        line = line.strip()
        if line.startswith("Server"):
            return line.split("=", 1)[1].strip()
    raise FeedError(f"no Server line in {mirrorlist}")


def _get(url, path=None, timeout=300):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if path is None:
            return response.read()
        with open(path, "wb") as handle:
            shutil.copyfileobj(response, handle)
    return path


class Keyring:
    """A private copy of the pacman keyring for gpg --verify."""

    def __init__(self, pubring="/etc/pacman.d/gnupg/pubring.gpg"):
        self.home = tempfile.mkdtemp(prefix="xray-keyring-")
        os.chmod(self.home, 0o700)
        shutil.copy(pubring, Path(self.home) / "pubring.gpg")

    def verify(self, path, signature):
        done = subprocess.run(
            ["gpg", "--homedir", self.home, "--no-default-keyring", "--keyring", f"{self.home}/pubring.gpg",
             "--trust-model", "always", "--verify", str(signature), str(path)],
            capture_output=True, text=True, check=False)
        return done.returncode == 0 and "Good signature" in done.stderr

    def close(self):
        shutil.rmtree(self.home, ignore_errors=True)


def parse_db(path):
    """{package name: {version, filename, sha256, csize, base}} from a pacman repository database."""

    packages = {}
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if not member.name.endswith("/desc"):
                continue
            text = archive.extractfile(member).read().decode("utf-8", "replace")
            fields, key = {}, None
            for line in text.splitlines():
                if line.startswith("%") and line.endswith("%"):
                    key = line.strip("%")
                elif line and key and key not in fields:
                    fields[key] = line
            if "NAME" in fields:
                packages[fields["NAME"]] = {
                    "version": fields.get("VERSION"), "filename": fields.get("FILENAME"),
                    "sha256": fields.get("SHA256SUM"), "csize": int(fields.get("CSIZE") or 0),
                    "base": fields.get("BASE"), "arch": fields.get("ARCH"), "pgpsig": fields.get("PGPSIG"),
                }
    return packages


def fetch_repo(repo, base_url, keyring, folder):
    """Download a repository database. Arch does not sign databases; each package carries its own signature."""

    url = base_url.replace("$repo", repo).replace("$arch", "x86_64")
    db = Path(folder) / f"{repo}.db"
    _get(f"{url}/{repo}.db", db)
    return url, parse_db(db)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def strong(gain):
    return gain["field"].startswith("class:") or gain["field"] in STRONG_FIELDS


def update(repos=DEFAULT_REPOS, paths=None, watch=None, max_mib=80, limit=None, base_url=None, progress=None):
    """Record new package versions in the log and the feed. Returns the new feed entries."""

    paths = {**default_paths(), **(paths or {})}
    for path in paths.values():
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    state = json.loads(Path(paths["state"]).read_text()) if Path(paths["state"]).exists() else {}
    base_url = base_url or mirror()
    keyring = Keyring()
    entries = []
    try:
        with tempfile.TemporaryDirectory(prefix="xray-feed-") as folder:
            for repo in repos:
                url, packages = fetch_repo(repo, base_url, keyring, folder)
                known = state.get(repo)
                if known is None:  # first run: start the feed from the current versions
                    state[repo] = {name: info["version"] for name, info in packages.items()}
                    continue
                changed = [(name, known.get(name), info) for name, info in sorted(packages.items())
                           if known.get(name) != info["version"] and (watch is None or name in watch)]
                for number, (name, old_version, info) in enumerate(changed[:limit] if limit else changed, 1):
                    if progress:
                        progress(repo, number, len(changed), name)
                    entry = _process(name, old_version, info, url, keyring, folder, paths, max_mib)
                    known[name] = info["version"]
                    if entry is not None:
                        entries.append(entry)
                        with open(paths["feed"], "a", encoding="utf-8") as feed:
                            feed.write(json.dumps(entry, sort_keys=True) + "\n")
                    Path(paths["state"]).write_text(json.dumps(state))
            Path(paths["state"]).write_text(json.dumps(state))
    finally:
        keyring.close()
    return entries


def _process(name, old_version, info, url, keyring, folder, paths, max_mib):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    entry = {"time": now, "package": name, "from": old_version, "to": info["version"]}
    if info["csize"] > max_mib << 20:
        return {**entry, "status": f"skipped: larger than {max_mib} MiB"}
    log = Path(paths["log"])
    logged = {(item["package"], item["version"]) for item in caplog.read_log(log)}
    archives = []
    try:
        if old_version and (name, old_version) not in logged:
            old_name = info["filename"].replace(f"-{info['version']}-", f"-{old_version}-", 1)
            old_path = Path(folder) / old_name
            old_url = f"{ARCHIVE}/{name[0]}/{name}/{old_name}"
            _get(old_url, old_path)
            _get(old_url + ".sig", Path(f"{old_path}.sig"))
            if not keyring.verify(old_path, f"{old_path}.sig"):
                return {**entry, "status": "the previous version's signature did not verify"}
            archives.append(old_path)
        if (name, info["version"]) not in logged:
            new_path = Path(folder) / info["filename"]
            _get(f"{url}/{info['filename']}", new_path)
            signature = Path(f"{new_path}.sig")
            if info.get("pgpsig"):
                signature.write_bytes(base64.b64decode(info["pgpsig"]))
            else:
                _get(f"{url}/{info['filename']}.sig", signature)
            if _sha256(new_path) != info["sha256"] or not keyring.verify(new_path, signature):
                new_path.unlink(missing_ok=True)
                return {**entry, "status": "the archive's signature or SHA-256 did not verify"}
            archives.append(new_path)
        if archives:
            caplog.add_archives(log, [str(path) for path in archives])
    except OSError as error:
        return {**entry, "status": f"download failed: {error}"}
    finally:
        for path in archives:
            Path(path).unlink(missing_ok=True)
            Path(f"{path}.sig").unlink(missing_ok=True)
    from .drift import drift

    versions = {item.get("version"): item for item in caplog.read_log(log) if item.get("package") == name}
    if old_version not in versions or info["version"] not in versions:
        return {**entry, "status": "recorded; no earlier version to compare with"}
    report = drift(versions[old_version]["files"], versions[info["version"]]["files"])
    gains = report["gains"]
    return {**entry, "status": "compared", "gains": gains, "strong": [gain for gain in gains if strong(gain)],
            "changed_files": len(report["changed"]), "added_files": len(report["added"])}


def read_feed(path=None):
    path = Path(path or default_paths()["feed"])
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def report_lines(entries, limit=50, strong_only=False):
    shown = [entry for entry in entries if entry.get("gains") and (entry.get("strong") or not strong_only)]
    gained = sum(1 for entry in entries if entry.get("gains"))
    strong_count = sum(1 for entry in entries if entry.get("strong"))
    lines = [f"{len(entries)} updates in the feed; {gained} gained capabilities; {strong_count} with strong gains", ""]
    for entry in shown[-limit:][::-1]:
        mark = "STRONG" if entry.get("strong") else "gain"
        lines.append(f"[{mark}] {entry['time'][:16]}  {entry['package']} {entry['from']} -> {entry['to']}")
        for gain in (entry.get("strong") or entry["gains"])[:6]:
            lines.append(f"    {gain['path']}: {gain['detail'][:140]}")
    if not shown:
        lines.append("No capability gains yet.")
    return lines


def report_html(entries, log_head=None):
    rows = []
    for entry in reversed(entries):
        if not entry.get("gains"):
            continue
        items = "".join(
            f"<li class='{'strong' if strong(gain) else ''}'><code>{html.escape(gain['path'])}</code> "
            f"{html.escape(gain['detail'][:200])}</li>" for gain in entry["gains"][:12])
        badge = "<span class='b s'>strong</span>" if entry.get("strong") else "<span class='b'>gain</span>"
        rows.append(f"<article>{badge} <b>{html.escape(entry['package'])}</b> "
                    f"{html.escape(str(entry['from']))} → {html.escape(str(entry['to']))} "
                    f"<time>{html.escape(entry['time'][:16].replace('T', ' '))} UTC</time><ul>{items}</ul></article>")
    total = len(entries)
    gained = sum(1 for entry in entries if entry.get("gains"))
    strong_count = sum(1 for entry in entries if entry.get("strong"))
    head = f"<p class='m'>Log head <code>{html.escape(log_head)}</code></p>" if log_head else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Arch capability feed</title>
<style>:root{{--bg:#f7f8fa;--ink:#1d2330;--m:#677084;--line:#d9dde5;--card:#fff;--s:#c2410c}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0d1117;--ink:#e6edf3;--m:#8b949e;--line:#2a313c;--card:#151b23;--s:#f97316}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}}
main{{max-width:900px;margin:0 auto;padding:24px 16px}}h1{{font-size:22px;margin:0 0 4px}}.m{{color:var(--m)}}
article{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}}
time{{color:var(--m);font-size:13px;float:right}}ul{{margin:6px 0 0;padding-left:18px}}li{{margin:2px 0}}
li.strong{{color:var(--s)}}code{{font:12.5px ui-monospace,monospace;word-break:break-all}}
.b{{font-size:11px;text-transform:uppercase;font-weight:700;border:1px solid var(--line);border-radius:999px;padding:1px 7px}}
.b.s{{color:var(--s);border-color:var(--s)}}</style></head><body><main>
<h1>Arch Linux capability feed</h1>
<p class="m">{total} package updates profiled by XRAY; {gained} gained capabilities, {strong_count} with strong gains
(a new call class, a loader hook, IFUNC resolvers, constructors, setuid). A gain is a lead to review, not a verdict.</p>
{head}{''.join(rows) or '<p>No capability gains yet.</p>'}</main></body></html>"""


TIMER = """[Unit]
Description=XRAY Arch capability feed (hourly)

[Timer]
OnCalendar=hourly
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
"""


def service(xray_path):
    return f"""[Unit]
Description=XRAY Arch capability feed update
After=network-online.target

[Service]
Type=oneshot
ExecStart={xray_path} feed update --quiet
Nice=10
"""
