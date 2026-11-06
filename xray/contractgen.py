"""Generate a capability contract from the evidence graph and, optionally, a traced run."""

from __future__ import annotations

import datetime
import os
import shlex
from collections import Counter
from pathlib import Path

from .contract import BASELINE_DEVICES, BASELINE_READ, Contract, Entry, matches
from .evidencestore import file_sha256

EXEC_LINKS = ("runs", "interpreter")
LOAD_LINKS = ("needs", "imports", "sources", "includes")
TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


def _home():
    return os.path.expanduser("~")


def portable(path, home=None):
    """Write paths under the home directory as ~/..."""

    home = home or _home()
    if path == home or path.startswith(home.rstrip("/") + "/"):
        return "~/" + path[len(home.rstrip("/")) + 1:] if path != home else "~/"
    return path


def _comment(link):
    evidence = min(link.evidence, key=lambda item: ("observed", "declared", "inferred", "guessed").index(item.basis))
    where = evidence.where()
    text = f"{link.basis}: {evidence.detail}"
    if where and where != evidence.detail:
        text += f" ({Path(where).name if ':' not in where else Path(where.rsplit(':', 1)[0]).name + ':' + where.rsplit(':', 1)[1]})"
    return text[:110]


def _baseline(path, home):
    return any(matches(pattern, path, home) for pattern in BASELINE_READ + BASELINE_DEVICES)


def from_graph(graph, contract=None):
    """Fill exec and load from what the evidence graph says the program reaches."""

    contract = contract or Contract(program=graph.root)
    contract.add("exec", graph.root, "the program itself")
    for link in graph.links.values():
        target = link.target
        onward = [step for step in graph.outgoing(target) if step.kind == "resolves_to"]
        if onward:
            target = onward[0].target
        node = graph.nodes.get(target)
        if node is None or not target.startswith("/") or not Path(target).exists():
            continue
        if link.kind in EXEC_LINKS:
            section = "load" if node.kind == "library" and link.kind == "interpreter" and "ld-" in node.label else "exec"
            contract.add(section, target, _comment(link))
        elif link.kind in LOAD_LINKS:
            contract.add("load", target, _comment(link))
    if graph.blind_spots:
        contract.notes.append(
            f"static reading has {len(graph.blind_spots)} blind spot(s); see `xray inspect {graph.root}`"
        )
    return contract


def _collapse(paths, threshold):
    """Group many paths in one directory into dir/*; keep the rest as they are."""

    per_dir = Counter(str(Path(path).parent) for path in paths)
    out = []
    for path in paths:
        parent = str(Path(path).parent)
        value = f"{parent.rstrip('/')}/*" if per_dir[parent] >= threshold else path
        if value not in out:
            out.append(value)
    return out


def add_observed(contract, observed, home=None):
    """Add what a traced run did, marked observed."""

    home = home or _home()
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    temp = [*TEMP_DIRS, *( [runtime] if runtime else [])]

    for path in observed.exec:
        _upgrade(contract, "exec", portable(os.path.realpath(path), home))

    reads = []
    for path in observed.read:
        real = os.path.realpath(path)
        if _baseline(path, home) or _baseline(real, home) or not Path(real).exists():
            continue
        value = portable(real, home)
        if value in contract.values("exec") or value in contract.values("load"):
            _upgrade(contract, "exec" if value in contract.values("exec") else "load", value)
        elif ".so" in Path(real).name and Path(real).is_file():
            _upgrade(contract, "load", value, "observed: loaded at run time")
        else:
            reads.append(real)
    for value in _collapse(reads, threshold=5):
        _upgrade(contract, "read", portable(value, home))

    writes = []
    for path in observed.write:
        if _baseline(path, home):
            continue
        path = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
        scratch = next((base for base in temp if path == base or path.startswith(base + "/")), None)
        writes.append(f"{scratch}/**" if scratch else path)
    for value in _collapse(writes, threshold=3):
        _upgrade(contract, "write", portable(value, home))

    for kind, protocol, where in observed.net:
        if kind == "unix":
            _upgrade(contract, "net", "unix", f"observed: {where}" if where else "observed")
        else:
            _upgrade(contract, "net", f"{kind} {protocol} {where}")
    return contract


def _upgrade(contract, section, value, comment="observed"):
    entries = contract.sections[section]
    for index, entry in enumerate(entries):
        if entry.value == value:
            if not entry.comment.startswith("observed"):
                entries[index] = Entry(value, f"observed; {entry.comment}" if entry.comment else comment)
            return
    contract.add(section, value, comment)


def generate(path, argv=None, depth=4, limit=300, timeout=30, packages=True):
    """Return a Contract for the program at path, from static evidence and an optional traced run."""

    from .evidence import build_evidence_graph

    graph = build_evidence_graph(path, max_depth=depth, max_files=limit, packages=packages)
    contract = from_graph(graph)
    try:
        contract.sha256 = file_sha256(graph.root)
    except OSError:
        pass
    for link in graph.outgoing(graph.root):
        if link.kind == "owned_by":
            contract.package = graph.nodes[link.target].label
    today = datetime.date.today().isoformat()
    if argv is None:
        contract.generated = f"{today} from static evidence"
        contract.notes.append("no run was traced: [read], [write] and [net] hold only what was observed (nothing)")
    else:
        from .observe import observe_run

        observed = observe_run([graph.root, *argv], timeout=timeout)
        add_observed(contract, observed)
        contract.generated = f"{today} from static evidence and a traced run"
        contract.workload = shlex.join([Path(graph.root).name, *argv])
        if observed.timed_out:
            contract.notes.append(f"the traced run was stopped after {timeout}s")
        elif observed.status:
            contract.notes.append(f"the traced run exited with status {observed.status}")
    return contract, graph
