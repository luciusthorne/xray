"""A pacman hook: show what each upgrade gains before it is installed, and optionally stop it.

pacman runs PreTransaction hooks after it has downloaded the new
packages and before it installs them. ``xray hook pacman`` reads the
names of the packages being upgraded on standard input (NeedsTargets),
finds each new archive in the package cache, compares it with the
installed version, and re-checks the capability pins of every contract
in /etc/xray/contracts that names a file from that package.

By default it only reports. With ``--block`` (or ``mode = block`` in
/etc/xray/hook.conf) it exits 1 when an upgrade gains a strong
capability (a new call class, a loader hook, IFUNC resolvers,
constructors, setuid) or breaks a contract, and the hook's AbortOnFail
stops the transaction. Packages listed in the ``allow`` line of
hook.conf are reported but never block.
"""

from __future__ import annotations

import os
import re
import tarfile
from pathlib import Path

from .archfeed import FEED_STRONG

HOOK = """[Trigger]
Operation = Upgrade
Type = Package
Target = *

[Action]
Description = XRAY: checking what upgrades gain...
When = PreTransaction
Exec = {xray} hook pacman
NeedsTargets
AbortOnFail
"""

CONFIG = """# XRAY pacman hook settings
# mode = report   (show gains, never stop an upgrade)
# mode = block    (stop the upgrade on a strong gain or a broken contract)
mode = report
# packages whose gains are shown but never block, separated by spaces
allow =
# optional: decide what blocks with a policy file (see `xray policy`) instead of "any strong gain"
# policy = /etc/xray/policy
"""


def pacman_conf(path="/etc/pacman.conf"):
    settings = {"CacheDir": ["/var/cache/pacman/pkg/"], "DBPath": "/var/lib/pacman/"}
    try:
        text = Path(path).read_text()
    except OSError:
        return settings
    cache = []
    for line in text.splitlines():
        match = re.match(r"^\s*(CacheDir|DBPath)\s*=\s*(\S+)", line)
        if match:
            if match.group(1) == "CacheDir":
                cache.append(match.group(2))
            else:
                settings["DBPath"] = match.group(2)
    if cache:
        settings["CacheDir"] = cache
    return settings


def read_config(path="/etc/xray/hook.conf"):
    config = {"mode": "report", "allow": set(), "policy": None}
    try:
        text = Path(path).read_text()
    except OSError:
        return config
    for line in text.splitlines():
        key, _, value = line.partition("=")
        key, value = key.strip(), value.split("#", 1)[0].strip()
        if key == "mode" and value in ("report", "block"):
            config["mode"] = value
        elif key == "allow":
            config["allow"] = set(value.split())
        elif key == "policy" and value:
            config["policy"] = value
    return config


def sync_versions(dbpath):
    """{package: (version, filename)} from every sync database."""

    found = {}
    sync = Path(dbpath) / "sync"
    for db in sorted(sync.glob("*.db")):
        try:
            with tarfile.open(db) as archive:
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
                        found.setdefault(fields["NAME"], (fields.get("VERSION"), fields.get("FILENAME")))
        except (OSError, tarfile.TarError):
            continue
    return found


def find_archive(name, versions, cache_dirs):
    version, filename = versions.get(name, (None, None))
    if not filename:
        return None, version
    for directory in cache_dirs:
        candidate = Path(directory) / filename
        if candidate.is_file():
            return candidate, version
    return None, version


def contracts_for(files, folder="/etc/xray/contracts"):
    """Contracts with an [exec] or [load] entry among files: [(contract path, Contract)]."""

    from .contract import ContractError, load_contract

    files = {os.path.realpath(path) for path in files}
    out = []
    for path in sorted(Path(folder).glob("*.contract")) if Path(folder).is_dir() else []:
        try:
            contract = load_contract(path)
        except ContractError:
            continue
        values = {os.path.realpath(value) for section in ("exec", "load") for value in contract.values(section)}
        if values & files or os.path.realpath(contract.program) in files:
            out.append((path, contract))
    return out


def pin_breaches(contract, new_profiles):
    """Entries whose pinned capabilities the new versions of their files exceed."""

    from .drift import stem
    from .profile import CLASSES

    by_path = {"/" + relative.lstrip("/"): profile for relative, profile in new_profiles.items()}
    by_stem = {}
    for path, profile in by_path.items():
        by_stem.setdefault((str(Path(path).parent), stem(path)), profile)
    out = []
    for section in ("exec", "load"):
        for entry in contract.sections[section]:
            profile = (by_path.get(entry.value) or by_path.get(os.path.realpath(entry.value))
                       or by_stem.get((str(Path(entry.value).parent), stem(entry.value))))
            if profile is None or not entry.attrs:
                continue
            pinned = entry.attr("caps")
            if pinned is not None:
                allowed = set() if pinned == "-" else set(pinned.split(","))
                for cls, symbols in sorted((profile.get("classes") or {}).items()):
                    if cls in CLASSES and cls not in allowed:
                        out.append(f"{entry.value}: would use {cls} ({', '.join(symbols)}); the contract allows caps={pinned}")
            for key, field in (("ifuncs", "ifuncs"), ("ctors", "constructors")):
                limit = entry.attr(key)
                if limit is not None and (profile.get(field) or 0) > int(limit):
                    out.append(f"{entry.value}: {field} would be {profile.get(field)}, the contract allows {key}={limit}")
    return out


def check_targets(names, conf=None, config=None, contracts_dir="/etc/xray/contracts", installed=None):
    """Return (report lines, block) for the packages being upgraded."""

    from .drift import drift, installed_files, opened, profiles

    conf = conf or pacman_conf()
    config = config or read_config()
    installed = installed or installed_files
    versions = sync_versions(conf["DBPath"])
    lines, blocking = [], []
    for name in names:
        archive, version = find_archive(name, versions, conf["CacheDir"])
        if archive is None:
            continue
        old_files = installed(name, everything=False)
        if not old_files:
            continue  # a new install: nothing to compare with
        with opened(str(archive)) as (_, _, files, _meta):
            new_profiles = profiles(files)
        old_profiles = profiles({path.lstrip("/"): path for path in old_files})
        report = drift(old_profiles, new_profiles)
        strong = [gain for gain in report["gains"]
                  if gain["field"].startswith("class:") or gain["field"] in FEED_STRONG]
        breaches = []
        for path, contract in contracts_for(installed(name, everything=True), contracts_dir):
            breaches += [f"{path.name}: {item}" for item in pin_breaches(contract, new_profiles)]
        if not report["gains"] and not breaches:
            continue
        mark = "STRONG" if strong or breaches else "gain"
        lines.append(f"[{mark}] {name} {version}: {len(report['gains'])} capability gain(s)")
        for gain in (strong or report["gains"])[:8]:
            lines.append(f"    {gain['path']}: {gain['detail'][:120]}")
        for item in breaches:
            lines.append(f"    contract {item}")
        if config.get("policy"):
            from . import policy

            denied = policy.violations(policy.load(config["policy"]), policy.gain_items(report["gains"], name))
            for item, rule in denied:
                lines.append(f"    policy: {item['detail'][:100]} (denied by line {rule.line})")
            if (denied or breaches) and name not in config["allow"]:
                blocking.append(name)
        elif (strong or breaches) and name not in config["allow"]:
            blocking.append(name)
    block = config["mode"] == "block" and bool(blocking)
    if block:
        lines.append(f"XRAY blocked the upgrade of {', '.join(blocking)}: strong capability gains or broken contracts.")
        lines.append("Review them, then allow the packages in /etc/xray/hook.conf or set mode = report.")
    return lines, block
