from pathlib import Path

from xray.analyzers import registry
from xray.entrypoints import command_kind


def _children(path, kind):
    """Return (name, target, target_kind) for what a file runs or needs.

    Shell scripts give the commands they run. ELF binaries give the
    libraries they need, as kind "library". Other files give nothing.
    A target of None means it could not be found.
    """

    result = []

    analyzer = registry.analyzer_for(path)

    if analyzer is None:
        return result

    for edge in analyzer.command_edges(path):
        if kind == "shell" and edge.kind != "runs":
            continue

        if edge.status == "external":
            result.append((edge.name or "unknown", None, "external"))
            continue

        if edge.status != "resolved" or edge.target is None:
            result.append((edge.name or "unknown", None, None))
            continue

        target = Path(edge.target)

        if kind == "elf" and edge.kind == "links":
            result.append((edge.name or target.name, target, "library"))
        else:
            name = edge.name or target.name

            result.append((name, target, command_kind(target)))

    return result


def chain_lines(
    path, max_depth=3, max_files=50, include_libraries=True
):
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

    def walk(node, kind, depth, prefix):
        if kind == "elf" and not include_libraries:
            return

        children = _children(node, kind)

        if depth >= max_depth:
            if children:
                state["depth_truncated"] = True
            return

        for index, (name, target, target_kind) in enumerate(children):
            last = index == len(children) - 1
            branch = "└── " if last else "├── "

            if target is None:
                marker = " (external)" if target_kind == "external" else " (not found)"
                lines.append(f"{prefix}{branch}{name}{marker}")
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

            if target_kind in (
                "shell", "elf", "python", "perl", "ruby", "javascript", "lua", "typescript", "c"
            ):
                extra = "    " if last else "│   "
                walk(target, target_kind, depth + 1, prefix + extra)

    walk(root, root_kind, 0, "")

    if state["truncated"]:
        lines.append(f"Truncated: file limit ({max_files}) reached")

    if state["depth_truncated"]:
        lines.append(f"Truncated: depth limit ({max_depth}) reached")

    return lines
