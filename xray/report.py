from pathlib import Path

from xray.entrypoints import command_kind
from xray.overview import overview_lines
from xray.provenance import package_of
from xray.sourcelookup import cached_source_files


def report_lines(path, markdown=False):
    """Return one report about a command: identity, overview, source files.

    It never downloads: source files are listed only when the source
    package is already cached.
    """

    path = Path(path).resolve()
    kind = command_kind(path)
    package = package_of(path)
    head = "## " if markdown else ""
    bullet = "- " if markdown else ""
    lines = [f"{head}Identity"]

    if not markdown:
        lines.append("────────")

    lines += [
        f"{bullet}Path: {path}",
        f"{bullet}Kind: {kind}",
        f"{bullet}Package: {package or 'not owned by an installed package'}",
        "",
        f"{head}Overview",
    ]

    if not markdown:
        lines.append("────────")

    body = overview_lines(path) or ["Nothing to show for this kind of file"]

    if markdown:
        lines += ["```", *body, "```"]
    else:
        lines += body

    lines += ["", f"{head}Source files"]

    if not markdown:
        lines.append("────────")

    files = cached_source_files(path)

    if files:
        lines += [f"{bullet}{f} ({len(n)} function(s))" for f, n in files.items()]
    elif kind == "elf":
        lines.append(f"{bullet}Not downloaded yet: run xray {path.name} --code to fetch")
    else:
        lines.append(f"{bullet}Read the script with xray {path.name} --code")

    return lines
