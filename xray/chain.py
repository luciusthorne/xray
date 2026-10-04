from pathlib import Path

from xray.command_analyzers import ShellAnalyzer
from xray.elfscan import scan_elf
from xray.entrypoints import command_kind, import_files
from xray.libresolve import find_library, ldconfig_cache


def _children(path, kind, cache):
    """Return (name, target, target_kind) for what a file runs or needs.

    Shell scripts give the commands they run. ELF binaries give the
    libraries they need, as kind "library". Other files give nothing.
    A target of None means it could not be found.
    """

    result = []

    if kind == "shell":
        for edge in ShellAnalyzer().edges(path):
            if edge.kind != "runs":
                continue

            if edge.status != "resolved":
                result.append((edge.name, None, None))
                continue

            target = Path(edge.target)
            result.append((edge.name, target, command_kind(target)))
    elif kind == "python":
        for target in import_files(path):
            name = target.name

            if name == "__init__.py":
                name = f"{target.parent.name}/__init__.py"

            result.append((name, target, command_kind(target)))
    elif kind == "elf":
        if cache["value"] is None:
            cache["value"] = ldconfig_cache()

        for name in scan_elf(path).needed:
            target = find_library(name, cache["value"])
            result.append((name, target, "library" if target else None))

    return result


def chain_lines(path, max_depth=3, max_files=50):
    """Return a tree of what a command runs and links to.

    Shell scripts expand into the commands they run, and ELF binaries
    list the libraries they need. Libraries are leaves and are not
    followed. A file that appears again is marked (seen) and not
    expanded, so cycles end. Following stops after max_depth levels,
    and no more than max_files files are listed. A last line says so
    when the limit left something out.
    """

    root = Path(path).resolve()
    root_kind = command_kind(root)
    lines = [f"{root} [{root_kind}]"]
    seen = {root}
    state = {"count": 1, "truncated": False, "depth_truncated": False}
    cache = {"value": None}

    def walk(node, kind, depth, prefix):
        children = _children(node, kind, cache)

        if depth >= max_depth:
            if children:
                state["depth_truncated"] = True
            return

        for index, (name, target, target_kind) in enumerate(children):
            last = index == len(children) - 1
            branch = "└── " if last else "├── "

            if target is None:
                lines.append(f"{prefix}{branch}{name} (not found)")
                continue

            label = f"{prefix}{branch}{name} -> {target} [{target_kind}]"

            if target in seen:
                lines.append(label + " (seen)")
                continue

            if state["count"] >= max_files:
                state["truncated"] = True
                continue

            seen.add(target)
            state["count"] += 1
            lines.append(label)

            if target_kind in ("shell", "elf", "python"):
                extra = "    " if last else "│   "
                walk(target, target_kind, depth + 1, prefix + extra)

    walk(root, root_kind, 0, "")

    if state["truncated"]:
        lines.append(f"Truncated: file limit ({max_files}) reached")

    if state["depth_truncated"]:
        lines.append(f"Truncated: depth limit ({max_depth}) reached")

    return lines
