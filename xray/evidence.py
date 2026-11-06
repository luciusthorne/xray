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

import shutil
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .elfscan import scan_elf
from .entrypoints import _interpreter, _read_start, command_kind, import_file_lines
from .libresolve import find_library, ldconfig_cache
from .locate import locate
from .perlscan import perl_inc, resolve_module, scan_perl
from .provenance import packages_of
from .shellscan import changes_path, command_lines, scan_shell

EVIDENCE_SCHEMA_VERSION = 1
BASES = ("observed", "declared", "inferred", "guessed")
_RANK = {basis: rank for rank, basis in enumerate(BASES)}

LINK_KINDS = (
    "runs",          # a script starts a command
    "sources",       # a shell script loads another file
    "imports",       # Python or Perl loads a module file
    "interpreter",   # shebang or PT_INTERP: what executes this file
    "needs",         # ELF DT_NEEDED: binary or library -> soname
    "resolves_to",   # soname or command name -> the file the system picks
    "owned_by",      # file -> installed package
    "executed",      # observed in a traced run
    "opened",        # observed in a traced run
)

FOLLOWED_KINDS = ("shell", "elf", "python", "perl")


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
            "truncated": list(self.truncated),
            "trace": self.trace,
        }


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
    def __init__(self, graph, max_depth, max_files):
        self.graph = graph
        self.max_depth = max_depth
        self.max_files = max_files
        self.queue = deque()
        self.files = set()
        self._ldcache = None
        self._inc = None

    def ldcache(self):
        if self._ldcache is None:
            self._ldcache = ldconfig_cache()
        return self._ldcache

    def file_node(self, path, depth):
        path = str(Path(path).resolve())
        if path in self.files:
            return path
        if len(self.files) >= self.max_files:
            self.graph.truncated.append(f"file limit ({self.max_files}) reached at {path}")
            return None
        self.files.add(path)
        self.graph.add_node(path, _file_kind(path))
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
        scan = scan_shell(path)
        lines = command_lines(path)
        path_changed = changes_path(path)
        if scan.dynamic:
            self.graph.blind(
                path,
                f"{scan.dynamic} command(s) are built at runtime (eval or variables) and are not in the graph",
            )
        if path_changed:
            self.graph.blind(path, "the script assigns PATH, so command lookups below are guesses")

        for name in scan.commands:
            line = lines.get(name)
            target = locate(name)
            said = Evidence("inferred", "shell-static", f"runs `{name}`", path, line)
            if target is None:
                node = self.graph.add_node(f"command:{name}", "command", name, resolved=False)
                self.graph.add_link(path, node.id, "runs", said)
                continue
            if "/" in name:
                target_id = self.file_node(target, depth)
                if target_id:
                    self.graph.add_link(path, target_id, "runs", said)
                continue
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

        for name in scan.sources:
            line = lines.get(name)
            candidate = Path(name).expanduser()
            if not candidate.is_absolute():
                candidate = Path(path).parent / candidate
            said = Evidence("inferred", "shell-static", f"sources `{name}`", path, line)
            if candidate.is_file():
                target_id = self.file_node(candidate, depth)
                if target_id:
                    self.graph.add_link(path, target_id, "sources", said)
            else:
                node = self.graph.add_node(f"command:{name}", "command", name, resolved=False)
                self.graph.add_link(path, node.id, "sources", said)

    # -- ELF -------------------------------------------------------------
    def elf(self, path, depth):
        scan = scan_elf(path)
        if scan.interpreter:
            evidence = Evidence("declared", "elf-interp", f"PT_INTERP {scan.interpreter}", path)
            target = Path(scan.interpreter)
            target_id = self.file_node(target, depth) if target.exists() else None
            if target_id:
                self.graph.add_link(path, target_id, "interpreter", evidence)
        for soname in scan.needed:
            soname_id = self.graph.add_node(f"soname:{soname}", "soname", soname).id
            self.graph.add_link(
                path, soname_id, "needs",
                Evidence("declared", "elf-dynamic", f"DT_NEEDED {soname}", path),
            )
            target = find_library(soname, self.ldcache())
            if target is None:
                self.graph.nodes[soname_id].attrs["resolved"] = False
                continue
            target_id = self.file_node(target, depth)
            if target_id:
                self.graph.add_link(
                    soname_id, target_id, "resolves_to",
                    Evidence("inferred", "ldconfig", f"{soname} -> {target} (ldconfig cache; RPATH and LD_LIBRARY_PATH not applied)"),
                )

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
        self.graph.blind(path, "Python imports built at runtime (importlib, __import__) and subprocess calls are not followed yet")

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


def build_evidence_graph(path, max_depth=4, max_files=300, packages=True):
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
    _Builder(graph, max_depth, max_files).run(root)

    if packages:
        files = [node.id for node in graph.nodes.values() if node.id.startswith("/")]
        owners = packages_of(files)
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
