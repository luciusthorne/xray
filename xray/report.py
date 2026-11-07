import re
import shlex
from pathlib import Path

from xray.entrypoints import command_kind
from xray.overview import overview_lines
from xray.provenance import package_manager, package_of
from xray.sourcelookup import cached_source_files, local_source_roots


def _code_span(value):
    """Wrap text in a Markdown code span without colliding with its backticks."""

    runs = [len(run) for run in re.findall(r"`+", value)]
    fence = "`" * (max(runs, default=0) + 1)
    padding = " " if value.startswith(("`", " ")) or value.endswith(("`", " ")) else ""
    return f"{fence}{padding}{value}{padding}{fence}"


def _language_lines(path, kind, bullet):
    """The language and toolchain line of a binary, when it can be told."""
    if kind != "elf":
        return []

    from xray.fingerprint import fingerprint

    try:
        found = fingerprint(path)
    except OSError:
        return []

    if found.language == "unknown":
        return []

    detail = f" ({found.toolchain})" if found.toolchain else ""
    return [f"{bullet}Language: {found.language}{detail}"]


def report_lines(path, markdown=False):
    """Return one report about a command: identity, overview, source files.

    It never downloads: source files are listed only when the source
    package is already cached.
    """

    path = Path(path).resolve()
    kind = command_kind(path)
    package = package_of(path)
    manager = package_manager(path) if package else None
    head = "## " if markdown else ""
    bullet = "- " if markdown else ""
    lines = [f"{head}Identity"]

    if not markdown:
        lines.append("────────")

    lines += [
        f"{bullet}Path: {_code_span(str(path)) if markdown else path}",
        f"{bullet}Kind: {kind}",
        f"{bullet}Package: {package or 'not owned by an installed package'}",
        *_language_lines(path, kind, bullet),
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
    code_command = f"xray {shlex.quote(str(path))} --code"

    mapped = None
    if not files and kind == "elf":
        from xray import codemap

        try:
            cmap = codemap.code_map(path)
        except (OSError, ValueError):
            cmap = None
        if cmap is not None and cmap.files:
            mapped = codemap.overview_lines(cmap, shlex.quote(str(path)), limit=12)

    if files:
        lines += [f"{bullet}{f} ({len(n)} function(s))" for f, n in files.items()]
    elif mapped:
        lines += ["```", *mapped, "```"] if markdown else mapped
    elif kind == "elf":
        if local_source_roots():
            guidance = (
                "Local source tree configured; use --code <function> to search it. "
                "Automatic file mapping needs function names in the binary"
            )
        elif manager == "pacman":
            from xray.debuginfod import configured as debuginfod_configured

            if debuginfod_configured():
                guidance = (
                    "Pacman source packages are not fetched; named --code tries "
                    "configured debuginfod and falls back to objdump"
                )
            else:
                guidance = (
                    "Pacman-owned source is not fetched automatically; --code falls "
                    "back to objdump disassembly when source/debug data is unavailable"
                )
        elif package:
            guidance = (
                "RPM source package not cached; named --code tries debuginfod, "
                "then source lookup uses dnf. "
                f"Run {code_command} to fetch supported package source"
            )
        else:
            from xray.debuginfod import configured as debuginfod_configured

            if debuginfod_configured():
                guidance = (
                    "No package source is available; named --code tries configured "
                    "debuginfod and falls back to objdump"
                )
            else:
                guidance = (
                    "No installed package source is available; --code uses objdump "
                    "disassembly when source/debug data is unavailable"
                )
        lines.append(f"{bullet}{_code_span(guidance) if markdown else guidance}")
    elif kind in {"shell", "perl", "ruby", "javascript", "lua", "typescript", "c", "python", "script"} \
            or kind in __import__("xray.analyzers", fromlist=["plugin_kinds"]).plugin_kinds():
        lines.append(
            f"{bullet}Script text: {_code_span(str(path))}; display it with "
            f"{_code_span(code_command)}"
            if markdown
            else f"{bullet}Script text: {path}; display it with {code_command}"
        )
    else:
        lines.append(f"{bullet}No source-file listing available for this file type")

    return lines
