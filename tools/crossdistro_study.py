"""Cross-distribution study: do Arch's and another distribution's builds of the same release differ?

--against debian (default) uses snapshot.debian.org; --against fedora uses
Fedora's Koji build system (kojipkgs.fedoraproject.org), the newest fcNN
build of the same upstream version.


For each package in an Arch capability log (tools/arch_capability_log.py),
the Debian source package is found through Repology, Debian's build of the
same upstream version is fetched from snapshot.debian.org (amd64 and
architecture-independent binary packages, no debug symbols, documentation
or headers), profiled and compared file by file with xray.crossbuild.
Results go to a JSON Lines file, one line per package; a summary is
printed at the end. Downloads are deleted after profiling.

    python tools/crossdistro_study.py --log ~/.local/share/xray/arch-capability-log.jsonl \\
        --out crossdistro.jsonl --limit 200
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from xray import caplog
from xray.crossbuild import compare_builds
from xray.drift import opened, profiles

USER_AGENT = "xray-crossdistro-study/1.1 (+https://github.com/luciusthorne/xray)"
SKIP_SUFFIXES = ("-dbgsym", "-dbg", "-doc", "-dev", "-docs", "-examples", "-l10n")
MAX_BYTES = 80 << 20


def get(url, timeout=120):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except OSError:
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
    return b""


def upstream(version):
    version = re.sub(r"^\d+:", "", version or "")
    if "-" in version:
        version = version.rsplit("-", 1)[0]
    return re.sub(r"[+~](dfsg|ds|repack|debian)\d*.*$", "", version)


def debian_sources(name):
    data = json.loads(get(f"https://repology.org/api/v1/project/{urllib.parse.quote(name)}"))
    time.sleep(1.1)  # Repology asks for at most one request per second
    sources = []
    for row in data:
        if row["repo"].startswith("debian") and row.get("srcname") and row["srcname"] not in sources:
            sources.append(row["srcname"])
    return sources


def debian_version(source, wanted):
    data = json.loads(get(f"https://snapshot.debian.org/mr/package/{urllib.parse.quote(source)}/"))
    for row in data.get("result", []):
        if upstream(row["version"]) == wanted and "really" not in row["version"]:
            return row["version"]
    return None


def debian_binaries(source, version):
    url = (f"https://snapshot.debian.org/mr/package/{urllib.parse.quote(source)}/"
           f"{urllib.parse.quote(version)}/allfiles?fileinfo=1")
    data = json.loads(get(url))
    out = []
    for binary in data.get("result", {}).get("binaries", []):
        name = binary["name"]
        if name.endswith(SKIP_SUFFIXES):
            continue
        for item in binary.get("files", []):
            if item["architecture"] not in ("amd64", "all"):
                continue
            info = data["fileinfo"][item["hash"]][0]
            out.append((info["name"], item["hash"], info.get("size", 0)))
    return out


KOJI = "https://kojipkgs.fedoraproject.org/packages"
FEDORA_SKIP = ("-debuginfo", "-debugsource", "-devel", "-doc", "-docs", "-static", "-tests", "-langpack")


def fedora_sources(name):
    data = json.loads(get(f"https://repology.org/api/v1/project/{urllib.parse.quote(name)}"))
    time.sleep(1.1)
    sources = []
    for row in data:
        if row["repo"].startswith("fedora") and row.get("srcname") and row["srcname"] not in sources:
            sources.append(row["srcname"])
    return sources


def fedora_build(source, wanted):
    """(release, [(file name, url, size)]) for the newest fcNN build of source at upstream version wanted."""

    try:
        listing = get(f"{KOJI}/{urllib.parse.quote(source)}/{urllib.parse.quote(wanted)}/").decode("utf-8", "replace")
    except OSError:
        return None, []
    releases = re.findall(r'href="([^"/]*\.fc(\d+))/"', listing)
    if not releases:
        return None, []
    release = max(releases, key=lambda item: (int(item[1]), caplog.vercmp(item[0], "0")))[0]
    files = []
    for arch in ("x86_64", "noarch"):
        try:
            page = get(f"{KOJI}/{source}/{wanted}/{release}/{arch}/").decode("utf-8", "replace")
        except OSError:
            continue
        for name, size in re.findall(r'href="([^"]+\.rpm)".*?(\d+[KMG]?)\s*$', page, re.MULTILINE):
            base = name.rsplit("-", 2)[0]
            if base.endswith(FEDORA_SKIP) or "-debuginfo" in name:
                continue
            files.append((name, f"{KOJI}/{source}/{wanted}/{release}/{arch}/{name}", size))
    return release, files


def compare_fedora(name, entry, row):
    for source in fedora_sources(name):
        release, files = fedora_build(source, row["upstream"])
        if release:
            row["fedora_source"], row["fedora_release"] = source, release
            break
    else:
        row["status"] = "no Fedora build of this upstream version"
        return
    fedora = {}
    with tempfile.TemporaryDirectory(prefix="xray-study-") as folder:
        for filename, url, _size in files:
            path = Path(folder) / filename
            path.write_bytes(get(url))
            if path.stat().st_size > MAX_BYTES:
                path.unlink()
                continue
            with opened(path) as (_, _, contents, _meta):
                for relative, profile in profiles(contents).items():
                    fedora[f"{filename}:{relative}"] = profile
            path.unlink()
            time.sleep(0.3)
    report = compare_builds(entry["files"], fedora)
    row.update(status="compared", fedora_rpms=[item[0] for item in files], **report)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=str(caplog.default_log_path().with_name("arch-capability-log.jsonl")))
    parser.add_argument("--out", default="crossdistro.jsonl")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--against", choices=("debian", "fedora"), default="debian")
    options = parser.parse_args()

    entries = caplog.read_log(options.log)
    newest = {}
    for entry in entries:
        name = entry["package"]
        if name not in newest or caplog.vercmp(entry["version"], newest[name]["version"]) > 0:
            newest[name] = entry
    out_path = Path(options.out)
    done = {json.loads(line)["package"] for line in out_path.read_text().splitlines()} if out_path.exists() else set()
    names = [name for name in dict.fromkeys(entry["package"] for entry in entries) if name in newest][:options.limit]

    with open(out_path, "a", encoding="utf-8") as results:
        for number, name in enumerate(names, 1):
            if name in done:
                continue
            entry = newest[name]
            row = {"package": name, "arch_version": entry["version"], "upstream": upstream(entry["version"])}
            try:
                if not any(profile.get("kind") == "elf" for profile in entry["files"].values()):
                    row["status"] = "no ELF files"
                elif options.against == "fedora":
                    compare_fedora(name, entry, row)
                else:
                    for source in debian_sources(name):
                        version = debian_version(source, row["upstream"])
                        if version:
                            row["debian_source"], row["debian_version"] = source, version
                            break
                    if "debian_version" not in row:
                        row["status"] = "no Debian build of this upstream version"
                    else:
                        binaries = debian_binaries(row["debian_source"], row["debian_version"])
                        if sum(size for _, _, size in binaries) > MAX_BYTES:
                            row["status"] = "Debian build too large"
                        else:
                            debian = {}
                            with tempfile.TemporaryDirectory(prefix="xray-study-") as folder:
                                for filename, digest, _ in binaries:
                                    path = Path(folder) / filename
                                    path.write_bytes(get(f"https://snapshot.debian.org/file/{digest}"))
                                    with opened(path) as (_, _, files, _meta):
                                        for relative, profile in profiles(files).items():
                                            debian[f"{filename}:{relative}"] = profile
                                    path.unlink()
                                    time.sleep(0.5)
                            report = compare_builds(entry["files"], debian)
                            row.update(status="compared", debian_binaries=[item[0] for item in binaries], **report)
            except (OSError, ValueError, KeyError) as error:
                row["status"] = f"error: {error}"
            results.write(json.dumps(row) + "\n")
            results.flush()
            print(f"[{number}/{len(names)}] {name}: {row['status']}"
                  + (f", {row['shared']} shared, {len(row['differences'])} differ, strong {row['strong']}"
                     if row.get("status") == "compared" else ""), flush=True)

    summarize(out_path)


def summarize(path):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    compared = [row for row in rows if row.get("status") == "compared" and row["shared"]]
    any_diff = [row for row in compared if row["differences"]]
    strong = [row for row in compared if row["strong"]]
    files = sum(row["shared"] for row in compared)
    print(f"\n{len(rows)} packages; {len(compared)} compared with shared files ({files} files)")
    print(f"{len(any_diff)} differ in some capability; {len(strong)} have a strong difference")
    for row in strong:
        print(f"  {row['package']} {row['upstream']}: {', '.join(row['strong'][:6])}")


if __name__ == "__main__":
    main()
