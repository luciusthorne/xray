"""The evidence graph: what a program reaches, and the proof for each step.

Every link records how it was found (method), where (file and line),
and how strong that proof is (basis). Bases, strongest first:

    observed  seen happening in a real run (strace)
    declared  stated by metadata the system itself acts on: an ELF
              DT_NEEDED entry or PT_INTERP, a shebang line, a package
              database's file ownership record
    inferred  read from code by static analysis, then resolved to a
              file the way the system would resolve it now (PATH, the
              ldconfig cache, Python and Perl search paths)
    guessed   a resolution XRAY could not stand behind, such as a PATH
              lookup in a script that changes PATH itself

A link may carry several pieces of evidence; its basis is the strongest
one. A path through the graph is only as strong as its weakest link.
Nothing here says a program is safe: blind spots lists what was not seen.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .elfscan import scan_elf
from .entrypoints import _interpreter, _read_start, command_kind, import_file_lines
from .libresolve import ldconfig_entries, resolve_library, search_path_risks
from .locate import locate
from .perlscan import perl_inc, resolve_module, scan_perl
from .provenance import packages_of
from .pyexec import python_exec
from .shellscan import shell_facts

EVIDENCE_SCHEMA_VERSION = 1
BASES = ("observed", "declared", "inferred", "guessed")
_RANK = {basis: rank for rank, basis in enumerate(BASES)}

LINK_KINDS = (
    "runs",          # a script starts a command
    "sources",       # a shell script loads another file
    "imports",       # Python, Perl, Ruby, JavaScript, TypeScript or Lua loads a module
    "includes",      # C #include
    "interpreter",   # shebang or PT_INTERP: what executes this file
    "needs",         # ELF DT_NEEDED: binary or library -> soname
    "dlopens",       # ELF dlopen metadata note: binary or library -> soname it may load on demand
    "resolves_to",   # soname or command name -> the file the system picks
    "owned_by",      # file -> installed package
    "executed",      # observed in a traced run
    "opened",        # observed in a traced run
)

FOLLOWED_KINDS = ("shell", "elf", "python", "perl", "ruby", "javascript", "typescript", "lua", "c", "lisp")
_READER_KINDS = ("ruby", "javascript", "typescript", "lua", "c", "lisp")

# Literal command starts in languages read with patterns rather than a parser.
_EXEC_PATTERNS = {
    "ruby": re.compile(
        r"""(?:\b(?:system|exec|spawn|IO\.popen|Open3\.\w+|Process\.spawn)\s*\(?\s*\[?\s*|%x[({\[]\s*|`\s*)"""
        r"""(?P<q>['"]?)(?P<cmd>[A-Za-z0-9_./+-]+)"""
    ),
    "javascript": re.compile(
        r"""\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(\s*(?P<q>['"`])(?P<cmd>[A-Za-z0-9_./+-]+)"""
    ),
}
_EXEC_PATTERNS["typescript"] = _EXEC_PATTERNS["javascript"]
# Emacs Lisp, Guile and Common Lisp ways to start a program with a literal name.
_EXEC_PATTERNS["lisp"] = re.compile(
    r"""\((?:call-process|process-file|shell-command|shell-command-to-string|async-shell-command|"""
    r"""system\*?|uiop:run-program|sb-ext:run-program|run-program)\s+(?:'\(\s*)?(?P<q>")(?P<cmd>[A-Za-z0-9_./+-]+)"""
    r"""|:command\s+(?:\(list\s+|'\()(?P<q2>")(?P<cmd2>[A-Za-z0-9_./+-]+)"""
)
_EXEC_PATTERNS["lua"] = re.compile(
    r"""\b(?:os\.execute|io\.popen)\s*\(?\s*(?P<q>['"])(?P<cmd>[A-Za-z0-9_./+-]+)"""
)


@dataclass(frozen=True)
class Evidence:
    """One reason to believe a link exists."""

    basis: str
    method: str
    detail: str
    file: str | None = None
    line: int | None = None

    def __post_init__(self):
        if self.basis not in _RANK:
            raise ValueError(f"Unknown evidence basis: {self.basis}")

    def where(self):
        if self.file is None:
            return None
        return f"{self.file}:{self.line}" if self.line else self.file

    def to_dict(self):
        return {
            "basis": self.basis,
            "method": self.method,
            "detail": self.detail,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class Node:
    """A thing in the graph: a file, a command or soname name, or a package.

    kind is the file kind from command_kind ("shell", "elf", ...),
    "library" for shared objects, "command" or "soname" for names that
    did not resolve to a file, or "package".
    """

    id: str
    kind: str
    label: str
    attrs: dict = field(default_factory=dict)

    def to_dict(self):
        return {"id": self.id, "kind": self.kind, "label": self.label, **self.attrs}


@dataclass
class Link:
    source: str
    target: str
    kind: str
    evidence: list = field(default_factory=list)

    @property
    def basis(self):
        return min((item.basis for item in self.evidence), key=_RANK.__getitem__)

    def to_dict(self):
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "basis": self.basis,
            "evidence": [item.to_dict() for item in self.evidence],
        }


def weakest(bases):
    """Return the weakest basis of a sequence (the strength of a path)."""

    return max(bases, key=_RANK.__getitem__)


class EvidenceGraph:
    def __init__(self, root):
        self.root = root
        self.nodes = {}
        self.links = {}
        self.blind_spots = []
        self.risks = []
        self.truncated = []
        self.trace = None

    def add_node(self, node_id, kind, label=None, **attrs):
        node = self.nodes.get(node_id)
        if node is None:
            node = Node(node_id, kind, label or Path(node_id).name or node_id, dict(attrs))
            self.nodes[node_id] = node
        else:
            node.attrs.update(attrs)
        return node

    def add_link(self, source, target, kind, evidence):
        if kind not in LINK_KINDS:
            raise ValueError(f"Unknown link kind: {kind}")
        key = (source, target, kind)
        link = self.links.get(key)
        if link is None:
            link = Link(source, target, kind)
            self.links[key] = link
        if evidence not in link.evidence:
            link.evidence.append(evidence)
        return link

    def outgoing(self, node_id):
        return [link for (source, _, _), link in self.links.items() if source == node_id]

    def risk(self, file, message):
        entry = {"file": file, "message": message}
        if entry not in self.risks:
            self.risks.append(entry)

    def blind_once(self, message):
        self.blind("*", message)

    def blind(self, file, message):
        entry = {"file": file, "message": message}
        if entry not in self.blind_spots:
            self.blind_spots.append(entry)

    def basis_counts(self):
        counts = dict.fromkeys(BASES, 0)
        for link in self.links.values():
            counts[link.basis] += 1
        return counts

    def find(self, query):
        """Return node ids matching a path, file name, command, soname or package."""

        query_path = Path(query).expanduser()
        resolved = str(query_path.resolve()) if "/" in query else None
        exact, loose = [], []
        for node in self.nodes.values():
            names = {node.id, node.label}
            if node.kind == "package":
                names.add(node.label.split()[0])
            if resolved is not None and node.id == resolved or query in names:
                exact.append(node.id)
            elif node.kind != "package" and (
                node.label.startswith(query + ".") or node.label.startswith(query + "-")
            ):
                loose.append(node.id)  # "libssl" matches libssl.so.3
        return exact or loose

    def paths(self, targets, max_paths=5, max_length=12, visits_per_node=3):
        """Return up to max_paths shortest link paths from the root to any target.

        Strongest links are tried first. A path that only leads on to a
        longer path to a target (a command name and the file it resolves
        to) is dropped in favour of the longer one.
        """

        targets = set(targets)
        found = []
        visits = {}
        queue = deque([(self.root, [])])
        while queue and len(found) < max_paths * 3:
            node, path = queue.popleft()
            if node in targets and path:
                found.append(path)
            if len(path) >= max_length:
                continue
            for link in sorted(self.outgoing(node), key=lambda item: (_RANK[item.basis], item.target)):
                if link.kind == "owned_by" and link.target not in targets:
                    continue
                if link.target == self.root or any(step.source == link.target for step in path):
                    continue
                if visits.get(link.target, 0) >= visits_per_node:
                    continue
                visits[link.target] = visits.get(link.target, 0) + 1
                queue.append((link.target, [*path, link]))

        def is_prefix(short, long):
            return len(short) < len(long) and long[: len(short)] == short

        kept = [path for path in found if not any(is_prefix(path, other) for other in found)]
        return kept[:max_paths]

    def to_dict(self):
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "root": self.root,
            "bases": list(BASES),
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "links": [link.to_dict() for link in self.links.values()],
            "blind_spots": list(self.blind_spots),
            "risks": list(self.risks),
            "truncated": list(self.truncated),
            "trace": self.trace,
        }


def _said(what, path, lines, via):
    """Evidence that a shell script names a command or file on these lines."""

    detail = what
    if len(lines) > 1:
        more = ", ".join(str(line) for line in lines[1:6])
        detail += f" (also line {more})"
    if via is None:
        return Evidence("inferred", "shell-parse", detail, path, lines[0])
    if via.startswith("$"):
        return Evidence(
            "guessed", "shell-variable",
            f"{detail} through {via}, which the script only sets to fixed values",
            path, lines[0],
        )
    return Evidence("inferred", "shell-parse", f"{detail} via {via}", path, lines[0])


def _ifunc_count(path):
    import subprocess

    try:
        done = subprocess.run(["readelf", "--dyn-syms", "-W", str(path)], capture_output=True, text=True,
                              errors="replace", check=False, env={**os.environ, "LC_ALL": "C"}, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    return sum(1 for line in done.stdout.splitlines() if " IFUNC " in line and " UND " not in line)


def _resolution_detail(soname, found):
    where = {
        "rpath": "DT_RPATH",
        "runpath": "DT_RUNPATH",
        "LD_LIBRARY_PATH": "LD_LIBRARY_PATH (this environment)",
        "ldconfig": "ldconfig cache",
        "default": "default library directory",
        "path": "path named in DT_NEEDED",
    }[found.method]
    detail = f"{soname} -> {found.path} ({where}"
    if found.method in ("rpath", "runpath", "LD_LIBRARY_PATH"):
        detail += f" {found.directory}"
    return detail + ")"


def _line_naming(lines, name):
    """The first line that mentions a written import name, or None."""

    if not name:
        return None
    for number, line in enumerate(lines, 1):
        if name in line:
            return number
    return None


def _shebang(path):
    start = _read_start(path)
    if not start or not start.startswith(b"#!"):
        return None
    return start.splitlines()[0].decode("utf-8", errors="replace")


def _file_kind(path):
    kind = command_kind(path)
    if kind in ("elf", "unknown") and ".so" in Path(path).name:
        return "library"
    return kind


class _Builder:
    def __init__(self, graph, max_depth, max_files, store=None, shared=None):
        self.graph = graph
        self.max_depth = max_depth
        self.max_files = max_files
        self.queue = deque()
        self.files = set()
        self.store = store
        self.shared = shared if shared is not None else {}
        self._ldcache = self.shared.get("ld")
        self._inc = self.shared.get("inc")
        self.root_rpath = ()
        self.collected = None

    def ld_entries(self):
        if self._ldcache is None:
            self._ldcache = ldconfig_entries()
        return self._ldcache

    def real(self, path):
        cache = self.shared.setdefault("real", {})
        key = str(path)
        if key not in cache:
            cache[key] = str(Path(path).resolve())
        return cache[key]

    def kind_of(self, path):
        cache = self.shared.setdefault("kind", {})
        if path not in cache:
            cache[path] = _file_kind(path)
        return cache[path]

    def file_node(self, path, depth):
        path = self.real(path)
        if self.collected is not None:
            # Reading one file on its own: note the file, the caller merges it.
            if path not in self.collected:
                self.collected.append(path)
                self.graph.add_node(path, self.kind_of(path))
            return path
        if path in self.files:
            return path
        if len(self.files) >= self.max_files:
            self.graph.truncated.append(f"file limit ({self.max_files}) reached at {path}")
            return None
        self.files.add(path)
        self.graph.add_node(path, self.kind_of(path))
        self.queue.append((path, depth))
        return path

    def run(self, root):
        self.file_node(root, 0)
        while self.queue:
            path, depth = self.queue.popleft()
            kind = self.graph.nodes[path].kind
            if depth >= self.max_depth:
                if kind in FOLLOWED_KINDS or kind == "library":
                    self.graph.nodes[path].attrs["not_expanded"] = "depth limit"
                continue
            self.expand(path, kind, depth + 1)

    def expand(self, path, kind, depth):
        """Add what one file reaches: from the store when it is unchanged."""

        inherited = self.root_rpath if kind == "library" else ()
        facts = self.store.get(path, inherited) if self.store is not None else None
        if facts is None:
            facts = self.local_facts(path, kind)
            if self.store is not None:
                self.store.put(path, inherited, facts)
        self.merge(facts, depth)
        if path == self.graph.root and facts.get("rpath") is not None:
            self.root_rpath = tuple(facts["rpath"])

    def local_facts(self, path, kind):
        """Read one file on its own and return what it reaches, as plain data."""

        main = self.graph
        scratch = EvidenceGraph(main.root)
        scratch.add_node(path, kind)
        self.graph, self.collected = scratch, []
        try:
            self.read_file(path, kind)
            collected = self.collected
        finally:
            self.graph, self.collected = main, None
        self.shared["ld"], self.shared["inc"] = self._ldcache, self._inc
        data = scratch.to_dict()
        return {
            "files": collected,
            "nodes": data["nodes"],
            "links": data["links"],
            "blind_spots": data["blind_spots"],
            "risks": data["risks"],
            "rpath": scratch.nodes[path].attrs.get("rpath"),
        }

    def merge(self, facts, depth):
        files = set(facts["files"])
        added = {path for path in facts["files"] if self.file_node(path, depth)}
        for node in facts["nodes"]:
            if node["id"] in files:
                continue
            attrs = {key: value for key, value in node.items() if key not in ("id", "kind", "label")}
            self.graph.add_node(node["id"], node["kind"], node["label"], **attrs)
        for link in facts["links"]:
            if (link["target"] in files and link["target"] not in added) or (
                link["source"] in files and link["source"] not in added
            ):
                continue
            for item in link["evidence"]:
                self.graph.add_link(link["source"], link["target"], link["kind"], Evidence(**item))
        for entry in facts["blind_spots"]:
            self.graph.blind(entry["file"], entry["message"])
        for entry in facts["risks"]:
            self.graph.risk(entry["file"], entry["message"])

    def read_file(self, path, kind):
        depth = 0
        line = _shebang(path)
        if line is not None and kind != "elf":
            self.shebang(path, line, depth)
        if kind == "shell":
            self.shell(path, depth)
        elif kind in ("elf", "library"):
            self.elf(path, depth)
        elif kind == "python":
            self.python(path, depth)
        elif kind == "perl":
            self.perl(path, depth)
        elif kind in _READER_KINDS:
            self.reader(path, kind, depth)
        elif kind not in ("unknown",):
            self.graph.blind(path, f"{kind} files are not followed yet")

    # -- shebang ---------------------------------------------------------
    def shebang(self, path, line, depth):
        tokens = line[2:].split()
        if not tokens:
            return
        program = tokens[0]
        name = _interpreter(line)
        if Path(program).name == "env" and name:
            if Path(program).is_file():
                # The kernel runs env itself; env then runs the named interpreter.
                env_id = self.file_node(program, depth)
                if env_id:
                    self.graph.add_link(path, env_id, "interpreter", Evidence("declared", "shebang", line.strip(), path, 1))
            target = locate(name)
            evidence = Evidence(
                "inferred", "shebang+PATH", f"{line.strip()} (env looks {name} up on PATH)", path, 1
            )
        else:
            target = Path(program) if Path(program).is_file() else None
            detail = line.strip()
            if target is not None and target.resolve() != target:
                detail += f" ({program} is a link to {target.resolve()})"
            evidence = Evidence("declared", "shebang", detail, path, 1)
        if target is None:
            node = self.graph.add_node(f"command:{name or program}", "command", name or program)
            self.graph.add_link(path, node.id, "interpreter", evidence)
            return
        target_id = self.file_node(target, depth)
        if target_id:
            self.graph.add_link(path, target_id, "interpreter", evidence)

    # -- shell -----------------------------------------------------------
    def shell(self, path, depth):
        facts = shell_facts(path)
        path_changed = bool(facts.path_lines)
        if facts.dynamic:
            lines = ", ".join(str(line) for line in sorted({line for line, _ in facts.dynamic})[:8])
            self.graph.blind(
                path,
                f"{len(facts.dynamic)} command(s) are built at runtime (eval or variables) "
                f"and are not in the graph (line {lines})",
            )
        if path_changed:
            lines = ", ".join(str(line) for line in facts.path_lines[:8])
            self.graph.blind(path, f"the script assigns PATH (line {lines}), so command lookups below are guesses")

        for name, lines in facts.commands.items():
            self.runs(path, name, _said(f"runs `{name}`", path, lines, facts.via.get(name)), depth, path_changed)

        for name, lines in facts.sources.items():
            candidate = Path(name).expanduser()
            if not candidate.is_absolute():
                candidate = Path(path).parent / candidate
            said = _said(f"sources `{name}`", path, lines, None)
            if "$" not in name and candidate.is_file():
                target_id = self.file_node(candidate, depth)
                if target_id:
                    self.graph.add_link(path, target_id, "sources", said)
            else:
                node = self.graph.add_node(f"command:{name}", "command", name, resolved=False)
                self.graph.add_link(path, node.id, "sources", said)

    def runs(self, path, name, said, depth, path_changed=False):
        """Link path to the command it runs, and the name to the file PATH picks."""

        target = locate(name)
        if target is None:
            node = self.graph.add_node(f"command:{name}", "command", name, resolved=False)
            self.graph.add_link(path, node.id, "runs", said)
            return
        if "/" in name:
            target_id = self.file_node(target, depth)
            if target_id:
                self.graph.add_link(path, target_id, "runs", said)
            return
        name_id = self.graph.add_node(f"command:{name}", "command", name).id
        self.graph.add_link(path, name_id, "runs", said)
        target_id = self.file_node(target, depth)
        if target_id:
            basis = "guessed" if path_changed else "inferred"
            self.graph.add_link(
                name_id,
                target_id,
                "resolves_to",
                Evidence(basis, "PATH", f"`{name}` is {target} on this machine's PATH"),
            )

    # -- ELF -------------------------------------------------------------
    def elf(self, path, depth):
        scan = scan_elf(path)
        if scan.interpreter:
            evidence = Evidence("declared", "elf-interp", f"PT_INTERP {scan.interpreter}", path)
            target = Path(scan.interpreter)
            target_id = self.file_node(target, depth) if target.exists() else None
            if target_id:
                self.graph.add_link(path, target_id, "interpreter", evidence)
        try:
            info = Path(path).stat()
        except OSError:
            info = None
        secure = bool(info and info.st_mode & (stat.S_ISUID | stat.S_ISGID))
        origin = Path(path).parent
        for kind, entries in (("RPATH", scan.rpath), ("RUNPATH", scan.runpath)):
            if entries:
                self.graph.nodes[path].attrs[kind.lower()] = list(entries)
            for message in search_path_risks(entries, origin, kind, scan.elf_class, info.st_uid if info else 0):
                self.graph.risk(path, message)
        if self.graph.nodes[path].kind == "library":
            from .profile import loader_hook

            ifuncs = _ifunc_count(path)
            facts = {"kind": "elf", "soname": Path(path).name, "needed": list(scan.needed), "ifuncs": ifuncs}
            if loader_hook(facts, path):
                self.graph.risk(path, f"links the dynamic loader and has {ifuncs} IFUNC resolver(s): code that runs "
                                      "inside the loader before main, the pattern of the 2024 xz backdoor")
        inherited = () if scan.runpath or self.graph.nodes[path].kind != "library" else self.root_rpath
        for soname in scan.needed:
            soname_id = self.graph.add_node(f"soname:{soname}", "soname", soname).id
            self.graph.add_link(
                path, soname_id, "needs",
                Evidence("declared", "elf-dynamic", f"DT_NEEDED {soname}", path),
            )
            found = resolve_library(
                soname, origin, scan.rpath, scan.runpath, inherited,
                scan.elf_class, scan.nodeflib, self.ld_entries(), secure=secure,
            )
            if found.path is None:
                self.graph.nodes[soname_id].attrs["resolved"] = False
                continue
            target_id = self.file_node(found.path, depth)
            if target_id:
                self.graph.add_link(
                    soname_id, target_id, "resolves_to",
                    Evidence("inferred", found.method, _resolution_detail(soname, found)),
                )
        for entry in scan.dlopen:
            found = None
            for soname in entry.sonames:
                found = resolve_library(
                    soname, origin, scan.rpath, scan.runpath, inherited,
                    scan.elf_class, scan.nodeflib, self.ld_entries(), secure=secure,
                )
                if found.path is not None:
                    break
            soname_id = self.graph.add_node(f"soname:{soname}", "soname", soname).id
            what = f"feature {entry.feature}, {entry.priority}" if entry.feature else entry.priority
            self.graph.add_link(
                path, soname_id, "dlopens",
                Evidence("declared", "elf-dlopen-note",
                         f"dlopen metadata ({what}): may load {' or '.join(entry.sonames)} on demand", path),
            )
            if found is None or found.path is None:
                if not any(link.kind == "resolves_to" for link in self.graph.outgoing(soname_id)):
                    self.graph.nodes[soname_id].attrs["resolved"] = False
                continue
            self.graph.nodes[soname_id].attrs.pop("resolved", None)
            target_id = self.file_node(found.path, depth)
            if target_id:
                self.graph.add_link(
                    soname_id, target_id, "resolves_to",
                    Evidence("inferred", found.method, _resolution_detail(soname, found)),
                )
        if not secure and os.environ.get("LD_LIBRARY_PATH"):
            self.graph.blind(path, "LD_LIBRARY_PATH is set here; the program may run with a different value")
        self.graph.blind_once("LD_PRELOAD and /etc/ld.so.preload can add libraries that no file names")

    # -- Python ----------------------------------------------------------
    def python(self, path, depth):
        for target, line in import_file_lines(path).items():
            if str(target) == path:
                continue
            target_id = self.file_node(target, depth)
            if target_id:
                self.graph.add_link(
                    path, target_id, "imports",
                    Evidence("inferred", "python-import", f"imports {Path(target).stem}", path, line),
                )
        started = python_exec(path)
        for name, lines in started.commands.items():
            how = started.via[name]
            if " through " in how:
                said = Evidence(
                    "guessed", "python-variable",
                    f"runs `{name}` with {how}, which the file only sets to literal values", path, lines[0],
                )
            else:
                said = Evidence("inferred", "python-exec", f"runs `{name}` via {how}", path, lines[0])
            self.runs(path, name, said, depth)
        if started.dynamic:
            where = ", ".join(str(line) for line in sorted({line for line, _ in started.dynamic})[:8])
            self.graph.blind(
                path, f"{len(started.dynamic)} command(s) are computed at run time and not in the graph (line {where})"
            )
        self.graph.blind(path, "Python imports built at runtime (importlib, __import__) are not followed")

    # -- Ruby, JavaScript, TypeScript, Lua, C ----------------------------
    def reader(self, path, kind, depth):
        from .analyzers import analyzer_for
        from .errors import AnalysisError, FileError

        try:
            if kind == "lisp":
                from .lisp import read_text

                text = read_text(path).splitlines()
            else:
                text = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, EOFError):
            return
        analyzer = analyzer_for(path)
        link_kind = "includes" if kind == "c" else "imports"
        method = "c-include" if kind == "c" else f"{kind}-import"
        try:
            edges = analyzer.command_edges(path) if analyzer else []
        except (AnalysisError, FileError, OSError, ValueError) as error:
            self.graph.blind(path, f"{kind} imports not read: {error}")
            edges = []
        for edge in edges:
            if edge.kind not in ("imports", "sources", "depends_on"):
                continue
            name = edge.name or edge.target or ""
            said = Evidence("inferred", method, f"{'includes' if kind == 'c' else 'imports'} {name}",
                            path, _line_naming(text, name))
            target = edge.target if edge.status == "resolved" else None
            if target is None and kind == "c" and edge.status == "external":
                for directory in ("/usr/local/include", "/usr/include"):
                    if (Path(directory) / name).is_file():
                        target = str(Path(directory) / name)
                        break
            if target and Path(target).is_file():
                target_id = self.file_node(target, depth)
                if target_id:
                    self.graph.add_link(path, target_id, link_kind, said)
                continue
            attrs = {"resolved": False} if edge.status == "unresolved" else {"external": True}
            node = self.graph.add_node(f"module:{name}", "command", name, **attrs)
            self.graph.add_link(path, node.id, link_kind, said)

        pattern = _EXEC_PATTERNS.get(kind)
        if pattern is None:
            return
        seen = set()
        for number, line in enumerate(text, 1):
            if line.lstrip().startswith(("#", "//", "--", ";")):
                continue
            for match in pattern.finditer(line):
                name = match.groupdict().get("cmd") or match.groupdict().get("cmd2")
                if name in seen:
                    continue
                seen.add(name)
                said = Evidence("inferred", f"{kind}-exec", f"starts `{name}` (literal command text)", path, number)
                self.runs(path, name, said, depth)
        self.graph.blind(path, f"{kind} commands built at run time are not followed; literal ones are matched by pattern")

    # -- Perl ------------------------------------------------------------
    def perl(self, path, depth):
        if self._inc is None:
            self._inc = perl_inc()
        for module, line in scan_perl(path).modules:
            target = resolve_module(module, self._inc)
            said = Evidence("inferred", "perl-use", f"use/require {module}", path, line)
            if target is None:
                node = self.graph.add_node(f"module:{module}", "command", module, resolved=False)
                self.graph.add_link(path, node.id, "imports", said)
                continue
            target_id = self.file_node(target, depth)
            if target_id:
                self.graph.add_link(path, target_id, "imports", said)


def build_evidence_graph(path, max_depth=4, max_files=300, packages=True, store=None, shared=None, owners=None):
    """Return the EvidenceGraph of everything a program reaches statically.

    Shell scripts, ELF binaries and shared libraries, Python and Perl
    files are followed up to max_depth steps; at most max_files files
    are added. With packages, each file is linked to the installed
    package that owns it, using one package-manager query.
    """

    target = locate(path) if "/" not in str(path) else Path(path).expanduser()
    if target is None or not Path(target).exists():
        raise FileNotFoundError(path)
    root = str(Path(target).resolve())
    graph = EvidenceGraph(root)
    _Builder(graph, max_depth, max_files, store, shared).run(root)

    if packages:
        files = [node.id for node in graph.nodes.values() if node.id.startswith("/")]
        if owners is None:
            owners = packages_of(files)
        else:
            owners = {file: owners[file] for file in files if file in owners}
        for file, (manager, owner) in owners.items():
            package = graph.add_node(f"package:{owner.split()[0]}", "package", owner, manager=manager)
            query = "pacman -Qo" if manager == "pacman" else "rpm -qf"
            graph.add_link(file, package.id, "owned_by", Evidence("declared", manager, f"{query}: {owner}"))
        if not owners and shutil.which("pacman") is None and shutil.which("rpm") is None:
            graph.blind(root, "no rpm or pacman database: package ownership not known")

    return graph


def add_trace(graph, result):
    """Merge a traced run (xray.trace.TraceResult) into the graph.

    Files the static graph already holds are marked observed. Files the
    run touched that static analysis did not predict are added as
    observed links from the root and listed under "unpredicted": they
    are either blind spots of static analysis or behavior worth a look.
    """

    unpredicted = []
    for kind, paths in (("executed", result.executed), ("opened", result.opened)):
        for raw in paths:
            resolved = str(Path(raw).resolve()) if Path(raw).exists() else raw
            node = graph.nodes.get(resolved)
            if node is not None:
                node.attrs["observed"] = True
                continue
            if kind == "opened" and not _interesting_open(resolved):
                continue
            graph.add_node(resolved, _file_kind(resolved) if Path(resolved).exists() else "unknown", observed=True)
            graph.add_link(
                graph.root, resolved, kind,
                Evidence("observed", "strace", f"{kind} during a traced run"),
            )
            unpredicted.append({"kind": kind, "path": resolved})
    graph.trace = {
        "status": result.status,
        "timed_out": result.timed_out,
        "unpredicted": unpredicted,
    }
    return unpredicted


def _interesting_open(path):
    """Opened files worth reporting: code and config, not locale or cache noise."""

    noise = ("/usr/share/locale/", "/usr/lib/locale/", "/usr/share/zoneinfo/", "/usr/lib/gconv/", "/usr/lib64/gconv/")
    return not path.startswith(noise) and not path.endswith((".mo", "/.cache"))
