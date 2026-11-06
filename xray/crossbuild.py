"""Compare two builds of the same release: what can one build do that the other cannot?

Two distributions building the same upstream version from the same
source should produce programs that are able to do the same things. A
difference in what they can do (a class of calls only one build makes,
code that runs before main in only one, a library hooking the dynamic
loader in only one) means something entered at build time: different
configure options, a distribution patch, or an injected payload like
the 2024 xz backdoor, which only reached Debian and RPM builds.

Files are paired by name, since distributions lay out directories
differently, and only files present in both builds are compared.
Differences are split into strong ones (capability classes, loader
hooks, IFUNC resolvers, constructors, setuid bits) and weak ones (extra
libraries, search paths), which configure options commonly explain.
"""

from __future__ import annotations

from pathlib import Path

from .drift import LOADER_HOOK, compare
from .profile import LOADER_NAMES, loader_hook

STRONG_FIELDS = ("loader-hook", "ifuncs", "constructors", "setuid", "setgid")


def by_name(profiles):
    """{file name: (path, profile)} for ELF files and scripts; the first path wins for a repeated name."""

    out = {}
    for path in sorted(profiles):
        out.setdefault(Path(path).name, (path, profiles[path]))
    return out


def _strong(change):
    if change["field"].startswith("class:") or change["field"] in STRONG_FIELDS:
        return True
    # Same source, one build depends on the dynamic loader's internals: no feature or configure option asks for that.
    return change["field"] == "needed" and bool(LOADER_NAMES.match(change["detail"].rsplit(": ", 1)[-1]))


def compare_builds(left, right):
    """Compare {path: profile} maps of two builds. Returns plain data.

    For every file name in both builds whose capabilities differ, lists
    what only the left build can do and what only the right build can do.
    """

    left_names, right_names = by_name(left), by_name(right)
    shared = sorted(set(left_names) & set(right_names))
    files = []
    for name in shared:
        left_path, left_profile = left_names[name]
        right_path, right_profile = right_names[name]
        if left_profile.get("kind") != right_profile.get("kind"):
            continue
        sides = {}
        for side, (old, old_path), (new, new_path) in (
            ("right", (left_profile, left_path), (right_profile, right_path)),
            ("left", (right_profile, right_path), (left_profile, left_path)),
        ):
            gains = [change for change in compare(old, new) if change["kind"] == "gain"]
            if loader_hook(new, new_path) and not loader_hook(old, old_path):
                gains.insert(0, {"kind": "gain", "field": "loader-hook", "detail": LOADER_HOOK})
            sides[side] = gains
        if sides["left"] or sides["right"]:
            files.append({
                "name": name, "left": left_path, "right": right_path,
                "only_left": sides["left"], "only_right": sides["right"],
                "strong": any(_strong(change) for change in sides["left"] + sides["right"]),
            })
    return {
        "shared": len(shared),
        "only_in_left": sorted(set(left_names) - set(right_names)),
        "only_in_right": sorted(set(right_names) - set(left_names)),
        "differences": files,
        "strong": [item["name"] for item in files if item["strong"]],
    }


def compare_lines(left_label, right_label, report):
    lines = [f"Comparing {left_label}", f"     with {right_label}", ""]
    lines.append(f"{report['shared']} files in both builds; {len(report['differences'])} differ in what they can do"
                 f" ({len(report['strong'])} with strong differences)")
    lines.append("")
    if not report["differences"]:
        lines.append("Both builds are able to do the same things.")
    for item in sorted(report["differences"], key=lambda entry: (not entry["strong"], entry["name"])):
        mark = "STRONG" if item["strong"] else "weak"
        lines.append(f"[{mark}] {item['name']}")
        for side, label in (("only_left", "only the first build"), ("only_right", "only the second build")):
            for change in item[side]:
                lines.append(f"    {label}: {change['detail']}")
    if report["only_in_left"] or report["only_in_right"]:
        lines.append("")
        lines.append(f"Not compared: {len(report['only_in_left'])} files only in the first build, "
                     f"{len(report['only_in_right'])} only in the second (distributions split packages differently).")
    lines.append("")
    lines.append("Strong: a capability class, a loader hook, IFUNC resolvers, constructors or setuid in one build only.")
    lines.append("Weak: libraries or search paths, which configure options commonly explain.")
    return lines
