"""Electron apps: find the JavaScript a launcher really runs, and read it.

An Electron app is a runtime (``electron``, or a renamed copy bundled
with the app) plus the app's code, usually in a ``resources/app.asar``
archive. XRAY finds the app from

- a launcher script that passes an ``.asar`` file or an app directory
  (one with ``package.json``) to a command, e.g. ``exec electron43
  /usr/lib/obsidian/app.asar "$@"``;
- an Electron binary: an ELF next to ``v8_context_snapshot.bin`` or
  ``snapshot_blob.bin`` with ``resources/app.asar`` or ``resources/app/``;
- the archive or app directory itself.

App code often loads more archives by name (Obsidian's ``app.asar`` is a
loader for ``obsidian.asar``): ``.asar`` names written as string
literals in the app's own JavaScript that exist next to it are read too,
and labelled as found by name.

Files are listed from the archive index without unpacking. Reading code
copies single members into XRAY's cache (see ``xray.asar``).
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import asar

_JS = (".js", ".mjs", ".cjs")
_TEXT = (*_JS, ".ts", ".json", ".html", ".css", ".txt", ".md", ".mm", ".c", ".cc", ".h")
_MARKERS = ("v8_context_snapshot.bin", "snapshot_blob.bin")
_ASAR_NAME = re.compile(r"""['"`]([\w.-]+\.asar)['"`]""")
_PATH_TOKEN = re.compile(r"""(?<![\w$])(/[^\s"'`$;|&()<>]+)""")
NOT_FOUND = "Not in the app: "
_MINIFIED = 2000   # a line this long marks a bundled/minified file


@dataclass
class Part:
    """One archive or app directory."""

    root: Path
    how: str
    files: list = field(default_factory=list)    # (name, size, unpacked)
    archive: bool = True
    package: dict = field(default_factory=dict)

    @property
    def label(self):
        return self.root.name

    def read(self, name, limit=None):
        if self.archive:
            return asar.read(self.root, name, limit)
        with open(self.root / name, "rb") as handle:
            return handle.read(limit if limit is not None else -1)

    def real(self, name):
        return asar.extract(self.root, name) if self.archive else self.root / name

    def entry(self):
        names = {name for name, _, _ in self.files}
        main = str(self.package.get("main") or "").removeprefix("./")
        for candidate in (main, main + ".js", main.rstrip("/") + "/index.js", "main.js", "index.js"):
            if candidate and candidate in names:
                return candidate
        return None


@dataclass
class App:
    parts: list
    launcher: Path | None = None
    how: str = ""

    @property
    def main(self):
        return self.parts[0]

    @property
    def name(self):
        package = self.main.package
        return package.get("productName") or package.get("name") or self.main.root.parent.name


def _app_directory(path):
    return path.is_dir() and (path / "package.json").is_file()


def _load_part(root, how):
    root = Path(root)
    if root.is_dir():
        files = []
        for item in sorted(root.rglob("*")):
            if item.is_file() and not item.is_symlink():
                files.append((item.relative_to(root).as_posix(), item.stat().st_size, False))
        part = Part(root, how, files, archive=False)
    else:
        part = Part(root, how, [(m.name, m.size, m.unpacked) for m in asar.members(root)])
    if any(name == "package.json" for name, _, _ in part.files):
        try:
            part.package = json.loads(part.read("package.json", 1 << 20))
        except (OSError, ValueError, asar.AsarError):
            part.package = {}
    return part


def _own(name):
    return not name.startswith("node_modules/") and "/node_modules/" not in name


def _more_parts(part, seen):
    """Archives next to `part` that its own JavaScript names in a string literal."""

    found = []
    budget = 8 << 20
    for name, size, _ in part.files:
        if not (name.endswith(_JS) and _own(name)) or size > budget:
            continue
        budget -= size
        try:
            text = part.read(name).decode("utf-8", "replace")
        except (OSError, asar.AsarError):
            continue
        for match in _ASAR_NAME.finditer(text):
            sibling = part.root.parent / match.group(1)
            line = text.count("\n", 0, match.start()) + 1
            if sibling.resolve() in seen or not asar.is_asar(sibling):
                continue
            seen.add(sibling.resolve())
            found.append((sibling, f"{part.label}:{name} line {line} names {match.group(1)!r} (found by name)"))
        if budget <= 0:
            break
    return found


def _electron_resources(binary):
    folder = Path(binary).resolve().parent
    if not any((folder / marker).is_file() for marker in _MARKERS):
        return None
    for candidate in (folder / "resources" / "app.asar", folder / "resources" / "app"):
        if (candidate.is_file() and asar.is_asar(candidate)) or _app_directory(candidate):
            return candidate
    return None


def _from_script(path):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if len(text) > 1 << 20:
        return None
    from .entrypoints import command_kind

    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for match in _PATH_TOKEN.finditer(line):
            candidate = Path(match.group(1))
            try:
                if candidate.is_file() and asar.is_asar(candidate):
                    return candidate, f"{path} line {number} passes {candidate} to the runtime"
                if _app_directory(candidate) and "electron" in line.lower():
                    return candidate, f"{path} line {number} passes the app directory {candidate} to electron"
                if candidate.is_file() and command_kind(candidate) == "elf":
                    resources = _electron_resources(candidate)
                    if resources is not None:
                        return resources, (f"{path} line {number} runs {candidate}, an Electron binary "
                                           f"(Chromium snapshot next to it) whose app is {resources}")
            except OSError:
                continue
    return None


def find_app(path):
    """The Electron app `path` runs or is, or None."""

    from .entrypoints import command_kind

    path = Path(path)
    found = None
    launcher = None
    try:
        if path.is_file() and asar.is_asar(path):
            found = path, f"{path} is an asar archive"
        elif _app_directory(path):
            found = path, f"{path} is an app directory"
        else:
            kind = command_kind(path)
            if kind == "shell":
                found, launcher = _from_script(path), path
            elif kind == "elf":
                resources = _electron_resources(path)
                if resources is not None:
                    found, launcher = (resources, f"{path} is an Electron binary; its app is {resources}"), path
    except OSError:
        return None
    if found is None:
        return None
    try:
        parts = [_load_part(*found)]
    except (OSError, asar.AsarError):
        return None
    seen = {parts[0].root.resolve()}
    index = 0
    while index < len(parts) and len(parts) < 8:
        for sibling, how in _more_parts(parts[index], seen):
            try:
                parts.append(_load_part(sibling, how))
            except (OSError, asar.AsarError):
                continue
        index += 1
    return App(parts, launcher, found[1])


# -- views --------------------------------------------------------------------


def _package_of(name):
    pieces = name.split("/")
    for index in range(len(pieces) - 1, -1, -1):
        if pieces[index] == "node_modules" and index + 1 < len(pieces):
            if pieces[index + 1].startswith("@") and index + 2 < len(pieces):
                return "/".join(pieces[index + 1:index + 3])
            return pieces[index + 1]
    return None


def _size(value):
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return str(value)


def _natives(part):
    return [(name, size, unpacked) for name, size, unpacked in part.files if name.endswith(".node")]


def overview_lines(app, hint=True):
    lines = [f"Electron app: {app.name}" + (f" {app.main.package['version']}" if app.main.package.get("version") else "")]
    lines.append(f"- found because {app.how}")
    for part in app.parts:
        own = [f for f in part.files if f[0].endswith(_JS) and _own(f[0])]
        packages = {_package_of(f[0]) for f in part.files} - {None}
        natives = _natives(part)
        entry = part.entry()
        lines.append(
            f"- {part.root}: {len(own)} JavaScript file(s) of its own ({_size(sum(f[1] for f in own))}), "
            f"{len(packages)} package(s) in node_modules"
            + (f", {len(natives)} native addon(s)" if natives else "")
            + (f"; entry {entry}" if entry else "")
        )
        if part is not app.main:
            lines.append(f"  loaded because {part.how}")
    if hint:
        target = app.launcher or app.main.root
        lines.append(f"Read the app: xray {target} --code   (files, then --code FILE or --code FUNCTION)")
    return lines


def map_lines(app, limit=40):
    """The app's files: its own code first, then packages, then native addons."""

    lines = overview_lines(app, hint=False)
    for part in app.parts:
        lines += ["", f"{part.root}" + (" (archive)" if part.archive else " (directory)")]
        own = [f for f in part.files if f[0].endswith(_JS + (".ts", ".html")) and _own(f[0])]
        own.sort(key=lambda f: (-f[1], f[0]))
        lines.append(f"  Own code ({len(own)} file(s)):")
        entry = part.entry()
        if len(own) > limit:
            folders = {}
            for name, size, _ in own:
                folder = "/".join(name.split("/")[:-1][:3]) or "."
                count, total = folders.get(folder, (0, 0))
                folders[folder] = (count + 1, total + size)
            lines.append(f"    By folder ({len(folders)}):")
            for folder, (count, total) in sorted(folders.items(), key=lambda item: -item[1][1])[:limit // 2]:
                lines.append(f"      {folder}/  ({count} files, {_size(total)})")
            if len(folders) > limit // 2:
                lines.append(f"      ... and {len(folders) - limit // 2} more folders")
            lines.append("    Entry and largest files:")
            own.sort(key=lambda f: f[0] != entry)
            limit_files = limit // 2
        else:
            limit_files = limit
        for name, size, unpacked in own[:limit_files]:
            notes = [_size(size)]
            if name == entry:
                notes.append("entry")
            if unpacked:
                notes.append("unpacked")
            lines.append(f"    {name}  ({', '.join(notes)})")
        if len(own) > limit_files:
            lines.append(f"    ... and {len(own) - limit_files} more")
        packages = {}
        for name, size, _ in part.files:
            package = _package_of(name)
            if package:
                count, total = packages.get(package, (0, 0))
                packages[package] = (count + 1, total + size)
        if packages:
            lines.append(f"  Packages in node_modules ({len(packages)}):")
            ordered = sorted(packages.items(), key=lambda item: (-item[1][1], item[0]))
            for package, (count, total) in ordered[:limit]:
                lines.append(f"    {package}  ({count} files, {_size(total)})")
            if len(ordered) > limit:
                lines.append(f"    ... and {len(ordered) - limit} more")
        natives = _natives(part)
        if natives:
            lines.append(f"  Native addons ({len(natives)}): compiled code the JavaScript loads with require()")
            for name, size, unpacked in natives[:limit]:
                where = str(part.root) + ".unpacked/" + name if unpacked else f"inside the archive: {name}"
                lines.append(f"    {name}  ({_size(size)}; {where})")
    target = app.launcher or app.main.root
    lines += ["", f"One file: xray {target} --code FILE      One function: xray {target} --code FUNCTION",
              f"Calls: xray {target} --callgraph [FUNCTION]"]
    return lines


def _find_file(app, name):
    name = name.removeprefix("./")
    matches = []
    for part in app.parts:
        for file, size, unpacked in part.files:
            if file == name or file.endswith("/" + name) or f"{part.label}/{file}" == name:
                matches.append((part, file, size))
    exact = [m for m in matches if m[1] == name or f"{m[0].label}/{m[1]}" == name]
    return exact or matches


def _shown(lines, start=1, limit=400, width=300):
    out = []
    for number, line in enumerate(lines[:limit], start):
        if len(line) > width:
            line = line[:width] + f" … ({len(line) - width} more characters)"
        out.append(f"{number:5d}  {line}")
    if len(lines) > limit:
        out.append(f"... and {len(lines) - limit} more lines")
    return out


def _integrity(part, file):
    if not part.archive:
        return None
    item = asar.member(part.root, file)
    result = asar.verified(part.root, item) if item else None
    if result is None:
        return "no integrity hash in the archive index"
    return "matches the SHA-256 in the archive index" if result else "DOES NOT MATCH the SHA-256 in the archive index"


def file_lines(app, part, file):
    text = part.read(file).decode("utf-8", "replace")
    lines = text.splitlines()
    header = [f"{part.root} → {file}  ({_size(len(text.encode()))}, {len(lines)} line(s))"]
    check = _integrity(part, file)
    if check:
        header.append(f"Integrity: {check}")
    if any(len(line) > _MINIFIED for line in lines[:50]):
        header.append("Bundled or minified: long lines are cut; function names below come from the parser")
    return [*header, "", *_shown(lines)]


def _symbols(path):
    from . import command_analyzers, python_analyzer  # noqa: F401  (register analyzers)
    from .analyzers import analyzer_for
    from .errors import XRAYError

    analyzer = analyzer_for(Path(path))
    if analyzer is None:
        return []
    try:
        return [s for s in analyzer.symbols(Path(path)) if s.kind in ("function", "method", "class")]
    except (OSError, ValueError, RuntimeError, XRAYError):
        return []


def _candidates(app, function, limit=64 << 20):
    """Own JavaScript files that mention `function` as a whole word, entry files first."""

    word = re.compile(rb"(?<![\w$])" + re.escape(function.encode()) + rb"(?![\w$])")
    found = []
    for part in app.parts:
        entry = part.entry()
        files = sorted((f for f in part.files if f[0].endswith(_JS) and _own(f[0])),
                       key=lambda f: (f[0] != entry, f[1]))
        budget = limit
        for file, size, _ in files:
            if size > budget:
                continue
            budget -= size
            try:
                if word.search(part.read(file)):
                    found.append((part, file))
            except (OSError, asar.AsarError):
                continue
    return found


def function_lines(app, function, say=lambda text: None):
    candidates = _candidates(app, function)
    for part, file in candidates[:12]:
        say(f"Parsing {part.label}:{file}")
        path = part.real(file)
        for symbol in _symbols(path):
            if symbol.name != function:
                continue
            text = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            end = (symbol.metadata or {}).get("end_line") or symbol.line
            if end == symbol.line and symbol.line <= len(text) and len(text[symbol.line - 1]) <= _MINIFIED:
                from .codeview import _brace_end

                end = _brace_end(text, symbol.line) or symbol.line
            body = text[symbol.line - 1:end]
            head = [f"{function} ({symbol.kind}) in {part.root} → {file}, lines {symbol.line}–{end}"]
            offsets = (symbol.metadata or {}).get("offsets")
            if body and offsets and any(len(line) > _MINIFIED for line in body):
                start, stop = offsets
                units = Path(path).read_text(encoding="utf-8", errors="replace").encode("utf-16-le")
                code = units[start * 2:stop * 2].decode("utf-16-le", errors="replace")
                shown = code[:4000]
                note = (f"Bundled or minified file: the definition is characters {start}–{stop}"
                        + (f"; showing the first 4000 of {len(code)}" if len(code) > 4000 else ""))
                return [*head, note, "", shown]
            return [*head, "", *_shown(body, symbol.line)]
    if candidates:
        named = ", ".join(f"{p.label}:{f}" for p, f in candidates[:8])
        return [f"{NOT_FOUND}no definition of {function!r} found by the parser; the name appears in {named}"]
    return [f"{NOT_FOUND}no file of {app.name} names {function!r}"]


def code_lines(app, name=None, say=lambda text: None):
    if name is None:
        return map_lines(app)
    matches = _find_file(app, name)
    if len(matches) == 1 or (matches and matches[0][1] == name):
        part, file, _ = matches[0]
        return file_lines(app, part, file)
    if len(matches) > 1:
        return [f"{name!r} matches {len(matches)} files; give more of the path:",
                *(f"- {p.label}:{f}" for p, f, _ in matches[:30])]
    return function_lines(app, name, say)


def callgraph_lines(app, focus=None, say=lambda text: None):
    from .scriptgraph import callgraph_lines as script_callgraph_lines
    from .scriptgraph import symbol_graph

    if focus is not None:
        for part, file in _candidates(app, focus)[:12]:
            say(f"Parsing {part.label}:{file}")
            graph = symbol_graph(part.real(file), "javascript")
            if graph is not None and focus in graph.functions:
                return [f"{part.root} → {file} (calls found by name)", "",
                        *script_callgraph_lines(graph, file, focus)]
        return [f"No function {focus!r} found in the JavaScript of {app.name}"]
    out = []
    for part in app.parts:
        entry = part.entry()
        if entry is None:
            continue
        say(f"Parsing {part.label}:{entry}")
        graph = symbol_graph(part.real(entry), "javascript")
        out += [f"{part.root} → {entry} (entry; calls found by name)"]
        out += script_callgraph_lines(graph, entry) if graph is not None else ["  no functions found"]
        out.append("")
    target = app.launcher or app.main.root
    out.append(f"One function, both directions, in any file: xray {target} --callgraph FUNCTION")
    return out or [f"No entry file found in {app.name}"]


# -- require() graph inside an archive ------------------------------------------

NODE_BUILTINS = frozenset(["assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib", "electron", "original-fs"])
_EXTENSIONS = ("", ".js", ".json", ".node", ".mjs", ".cjs")


def _normal(name):
    parts = []
    for piece in name.split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(piece)
    return "/".join(parts)


def _as_file_or_directory(names, part, base):
    for extension in _EXTENSIONS:
        if base + extension in names:
            return base + extension
    manifest = f"{base}/package.json"
    if manifest in names:
        try:
            main = str(json.loads(part.read(manifest, 1 << 20)).get("main") or "")
        except (OSError, ValueError, asar.AsarError):
            main = ""
        if main:
            target = _normal(f"{base}/{main}")
            if target is not None:
                for extension in _EXTENSIONS:
                    if target + extension in names:
                        return target + extension
                for index in ("/index.js", "/index.json", "/index.node"):
                    if target + index in names:
                        return target + index
    for index in ("/index.js", "/index.json", "/index.node"):
        if base + index in names:
            return base + index
    return None


def resolve_require(part, names, member, spec):
    """("member", name) | ("builtin", module) | ("unresolved", spec) for require(spec) in member."""

    bare = spec.removeprefix("node:")
    if spec.startswith("node:") or bare.split("/")[0] in NODE_BUILTINS:
        return "builtin", bare.split("/")[0] if bare.split("/")[0] in NODE_BUILTINS else bare
    folder = "/".join(member.split("/")[:-1])
    if spec.startswith(("./", "../")) or spec in (".", ".."):
        base = _normal(f"{folder}/{spec}" if folder else spec)
        found = _as_file_or_directory(names, part, base) if base is not None else None
        return ("member", found) if found else ("unresolved", spec)
    if spec.startswith("/"):
        return "unresolved", spec
    pieces = folder.split("/") if folder else []
    for depth in range(len(pieces), -1, -1):
        if depth and pieces[depth - 1] == "node_modules":
            continue
        prefix = "/".join(pieces[:depth])
        base = _normal(f"{prefix}/node_modules/{spec}" if prefix else f"node_modules/{spec}")
        found = _as_file_or_directory(names, part, base) if base is not None else None
        if found:
            return "member", found
    return "unresolved", spec


def _member_imports(part, member):
    """Literal require()/import specifiers of one JavaScript member, from the Node parser."""

    from .javascript_analyzer import _read

    _, data = _read(part.real(member))
    return [item["name"] for item in data.get("imports", [])]


def _line_of(text, needle):
    at = text.find(needle)
    return text.count("\n", 0, at) + 1 if at >= 0 else None


def require_graph(part, limit=300, budget=64 << 20):
    """Walk require() from the entry file of an archive.

    Returns (visited, links, unread): visited members in order; links
    [(member, spec, line, (kind, target))]; unread [(member, reason)].
    """

    from .errors import XRAYError

    names = {name for name, _, _ in part.files}
    sizes = {name: size for name, size, _ in part.files}
    entry = part.entry()
    if entry is None:
        return [], [], []
    queue, seen, links, unread = [entry], {entry}, [], []
    visited = []
    while queue and len(visited) < limit:
        member = queue.pop(0)
        visited.append(member)
        if not member.endswith(_JS):
            continue
        if sizes.get(member, 0) > budget:
            unread.append((member, "larger than the reading budget"))
            continue
        budget -= sizes.get(member, 0)
        try:
            text = part.read(member).decode("utf-8", "replace")
            specs = _member_imports(part, member)
        except (OSError, ValueError, RuntimeError, XRAYError, asar.AsarError) as error:
            unread.append((member, str(error)[:120]))
            continue
        for spec in dict.fromkeys(specs):
            resolved = resolve_require(part, names, member, spec)
            line = _line_of(text, f"'{spec}'") or _line_of(text, f'"{spec}"') or _line_of(text, f"`{spec}`")
            links.append((member, spec, line, resolved))
            if resolved[0] == "member" and resolved[1] not in seen:
                seen.add(resolved[1])
                queue.append(resolved[1])
    if queue:
        unread.append((queue[0], f"member limit ({limit}) reached; {len(queue)} more not read"))
    return visited, links, unread
