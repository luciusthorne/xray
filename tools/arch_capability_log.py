"""Build a capability log over the most popular Arch Linux packages.

For each of the top N packages on pkgstats.archlinux.de, the current
version (from the first mirror in /etc/pacman.d/mirrorlist) and the
version before it (from archive.archlinux.org) are downloaded, their
signatures verified against the pacman keyring, profiled into the log
(oldest first) and deleted. Nothing about this machine goes into the
log: only official packages.

    python tools/arch_capability_log.py --top 500 --log arch-capability-log.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from functools import cmp_to_key
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from xray import caplog

USER_AGENT = "xray-capability-log/1.1 (+https://github.com/luciusthorne/xray)"
ARCHIVE = "https://archive.archlinux.org/packages"


def fetch(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def download(url, path, timeout=300):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response, open(path, "wb") as handle:
        shutil.copyfileobj(response, handle)


def top_packages(count):
    names, offset = [], 0
    while len(names) < count:
        data = json.loads(fetch(f"https://pkgstats.archlinux.de/api/packages?limit=250&offset={offset}"))
        batch = [item["name"] for item in data["packagePopularities"]]
        if not batch:
            break
        names.extend(batch)
        offset += len(batch)
    return names[:count]


def sync_info(name):
    done = subprocess.run(["pacman", "-Si", name], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        return None
    info = {}
    for line in done.stdout.splitlines():
        key, _, value = line.partition(":")
        info.setdefault(key.strip(), value.strip())
    size = info.get("Download Size", "0 B").split()
    factor = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}.get(size[-1], 1)
    return {"repo": info.get("Repository"), "version": info.get("Version"), "arch": info.get("Architecture"),
            "size": float(size[0]) * factor if size else 0}


def mirror():
    for line in Path("/etc/pacman.d/mirrorlist").read_text().splitlines():
        if line.startswith("Server"):
            return line.split("=", 1)[1].strip()
    raise SystemExit("no Server in /etc/pacman.d/mirrorlist")


def previous_version(name, current, arch):
    listing = fetch(f"{ARCHIVE}/{name[0]}/{name}/").decode("utf-8", "replace")
    pattern = re.compile(rf'href="({re.escape(name)}-([^"]+?)-({arch})\.pkg\.tar\.(?:zst|xz))"')
    # epochs are URL-encoded in the listing (1%3A26.2.5-1)
    found = {urllib.parse.unquote(version): filename for filename, version, _ in pattern.findall(listing)}
    older = [version for version in found if caplog.vercmp(version, current) < 0]
    if not older:
        return None
    best = max(older, key=cmp_to_key(caplog.vercmp))
    return best, f"{ARCHIVE}/{name[0]}/{name}/{found[best]}"


def verify(path, keyring_home):
    done = subprocess.run(["gpg", "--homedir", keyring_home, "--no-default-keyring", "--keyring",
                           f"{keyring_home}/pubring.gpg", "--trust-model", "always", "--verify",
                           f"{path}.sig", str(path)], capture_output=True, text=True, check=False)
    return done.returncode == 0 and "Good signature" in done.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--top", type=int, default=500)
    parser.add_argument("--log", default="arch-capability-log.jsonl")
    parser.add_argument("--max-size", type=int, default=80, help="skip packages larger than this many MiB")
    options = parser.parse_args()

    log = Path(options.log)
    logged = {(entry["package"], entry["version"]) for entry in caplog.read_log(log)}
    base = mirror()
    names = top_packages(options.top)
    skipped = []
    with tempfile.TemporaryDirectory(prefix="xray-arch-") as work:
        keyring = Path(work) / "gnupg"
        keyring.mkdir(mode=0o700)
        shutil.copy("/etc/pacman.d/gnupg/pubring.gpg", keyring / "pubring.gpg")
        for number, name in enumerate(names, 1):
            info = sync_info(name)
            if info is None:
                skipped.append((name, "not in the sync databases"))
                continue
            if info["size"] > options.max_size << 20:
                skipped.append((name, f"larger than {options.max_size} MiB"))
                continue
            current = (info["version"], base.replace("$repo", info["repo"]).replace("$arch", "x86_64")
                       + f"/{name}-{info['version']}-{info['arch']}.pkg.tar.zst")
            try:
                older = previous_version(name, info["version"], info["arch"])
            except OSError as error:
                older = None
                skipped.append((name, f"archive listing failed: {error}"))
            archives = []
            for version, url in [item for item in (older, current) if item]:
                if (name, version) in logged:
                    continue
                path = Path(work) / url.rsplit("/", 1)[1]
                try:
                    download(url, path)
                    download(url + ".sig", Path(f"{path}.sig"))
                except OSError as error:
                    skipped.append((f"{name} {version}", f"download failed: {error}"))
                    continue
                if not verify(path, str(keyring)):
                    skipped.append((f"{name} {version}", "signature did not verify"))
                    path.unlink(missing_ok=True)
                    continue
                archives.append(str(path))
            if archives:
                caplog.add_archives(log, archives)
            for path in archives:
                Path(path).unlink(missing_ok=True)
                Path(f"{path}.sig").unlink(missing_ok=True)
            print(f"[{number}/{len(names)}] {name}: {len(archives)} archive(s)", flush=True)
            time.sleep(0.2)
    _ok, head, message = caplog.verify(caplog.read_log(log))
    print(message)
    print(f"head {head}")
    for item, reason in skipped:
        print(f"skipped {item}: {reason}")


if __name__ == "__main__":
    main()
