"""``xray contract generate|check|enforce|minimize``."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from .contract import Contract, ContractError, Entry, load_contract
from .errors import CLIError

USAGE = """usage: xray contract generate <command> [-o FILE] [--trace -- ARGS...]
       xray contract check <contract> [--trace -- ARGS...] [--strict] [--json]
       xray contract enforce <contract> [--read PATH] [--write PATH] [--dry-run] -- ARGS...
       xray contract minimize <contract> [-o FILE] [--all] [--max-runs N] -- ARGS..."""


def _split(argv):
    """Split argv at the first --: (options, workload args or None)."""

    if "--" in argv:
        index = argv.index("--")
        return argv[:index], argv[index + 1:]
    return argv, None


def _parser(name):
    parser = argparse.ArgumentParser(prog=f"xray contract {name}")
    if name == "generate":
        parser.add_argument("command")
        parser.add_argument("-o", "--output", metavar="FILE")
        parser.add_argument("--trace", action="store_true", help="also RUN the command (args after --) under strace")
        parser.add_argument("--workloads", metavar="FILE", help="trace every workload in FILE (one command line per line)")
        parser.add_argument("--depth", type=int, default=4)
        parser.add_argument("--limit", type=int, default=300)
        parser.add_argument("--timeout", type=int, default=30)
        parser.add_argument("--no-packages", action="store_true")
    else:
        parser.add_argument("contract")
    if name == "check":
        parser.add_argument("--trace", action="store_true", help="also RUN the program (args after --) and check what it does")
        parser.add_argument("--strict", action="store_true", help="a changed program file counts as a breach")
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--depth", type=int, default=4)
        parser.add_argument("--limit", type=int, default=300)
        parser.add_argument("--timeout", type=int, default=30)
    if name == "enforce":
        parser.add_argument("--read", action="append", default=[], metavar="PATH", help="also allow reading PATH")
        parser.add_argument("--write", action="append", default=[], metavar="PATH", help="also allow writing PATH")
        parser.add_argument("--dry-run", action="store_true", help="print the rules and command; run nothing")
    if name == "minimize":
        parser.add_argument("-o", "--output", metavar="FILE")
        parser.add_argument("--workloads", metavar="FILE", help="keep every workload in FILE working (one per line)")
        parser.add_argument("--all", action="store_true", help="also try removing declared libraries and the loader")
        parser.add_argument("--max-runs", type=int, default=200)
        parser.add_argument("--timeout", type=int, default=30)
        parser.add_argument("--ignore-stderr", action="store_true", help="only exit status and stdout must stay the same")
    return parser


def run_contract(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    name, rest = argv[0], argv[1:]
    if name not in ("generate", "check", "enforce", "minimize"):
        raise CLIError(USAGE)
    options_argv, workload = _split(rest)
    parser = _parser(name)
    try:
        options = parser.parse_args(options_argv)
    except SystemExit as stop:
        if stop.code in (0, None):
            return 0
        raise CLIError(f"usage: {parser.format_usage().strip()}") from None
    try:
        return {"generate": _generate, "check": _check, "enforce": _enforce, "minimize": _minimize}[name](options, workload)
    except ContractError as error:
        raise CLIError(f"contract: {error}") from None


def _write(contract, output):
    text = contract.render()
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"wrote {output}", file=sys.stderr)
    else:
        print(text, end="")


def _generate(options, workload):
    from .contractgen import generate

    workloads = read_workloads(options.workloads) if options.workloads else None
    if workloads and (options.trace or workload):
        raise CLIError("use either --workloads FILE or --trace -- ARGS")
    if options.trace and workload is None:
        workload = []
    if not options.trace and workload:
        raise CLIError("arguments after -- are for --trace")
    try:
        contract, _ = generate(
            options.command, workload if options.trace else None, depth=options.depth,
            limit=options.limit, timeout=options.timeout, packages=not options.no_packages,
            workloads=workloads,
        )
    except FileNotFoundError:
        raise CLIError(f"Not found on PATH or disk: {options.command}") from None
    _write(contract, options.output)
    return 0


# -- check -------------------------------------------------------------------

def check_contract(contract, graph, observed=None, strict=False):
    """Compare a program's evidence (and an observed run) with its contract.

    Returns {"breaches": [...], "unused": [...], "changed": bool}. A breach
    is something the program reaches or did that the contract does not
    allow; each carries the evidence (a proof chain for static ones).
    """

    from .contractgen import EXEC_LINKS, LOAD_LINKS, portable
    from .evidencestore import file_sha256

    breaches = []
    seen_static = set()
    changed = False
    if contract.sha256:
        try:
            changed = file_sha256(contract.program) != contract.sha256
        except OSError:
            changed = True
    if changed and strict:
        breaches.append({"section": "program", "value": contract.program, "how": "static",
                         "detail": "the program file changed since the contract was written (sha256 differs)"})

    for link in graph.links.values():
        target = link.target
        onward = [step for step in graph.outgoing(target) if step.kind == "resolves_to"]
        if onward:
            target = onward[0].target
        if not target.startswith("/") or not os.path.exists(target):
            continue
        if link.kind in EXEC_LINKS:
            section = "load" if link.kind == "interpreter" and Path(target).name.startswith("ld-") else "exec"
        elif link.kind in LOAD_LINKS:
            section = "load"
        else:
            continue
        seen_static.add(portable(target))
        if contract.allows(section, target) or any(
            item["section"] == section and item["value"] == target for item in breaches
        ):
            continue
        chain = graph.paths([graph.nodes[target].id], max_paths=1)
        breaches.append({
            "section": section, "value": target, "how": "static",
            "detail": f"{link.basis}: {link.evidence[0].detail}",
            "chain": [item.to_dict() for item in chain[0]] if chain else [],
        })

    for section in ("exec", "load"):
        for entry in contract.sections[section]:
            breaches.extend(_capability_breaches(section, entry))

    observed_values = set()
    if observed is not None:
        checks = [("exec", path) for path in observed.exec] + [("read", path) for path in observed.read] + [
            ("write", path) for path in observed.write]
        for section, path in checks:
            real = os.path.realpath(path) if section != "write" else os.path.join(
                os.path.realpath(os.path.dirname(path)), os.path.basename(path))
            observed_values.add(portable(real))
            if contract.allows(section, real) or contract.allows(section, path):
                continue
            item = {"section": section, "value": real, "how": "observed", "detail": f"{section} during the traced run"}
            if item not in breaches:
                breaches.append(item)
        for kind, protocol, where in observed.net:
            allowed = contract.net_allows("unix") if kind == "unix" else contract.net_allows(kind, protocol, where)
            if not allowed:
                value = "unix" if kind == "unix" else f"{kind} {protocol} {where}"
                item = {"section": "net", "value": value, "how": "observed",
                        "detail": f"{kind} {where} during the traced run"}
                if item not in breaches:
                    breaches.append(item)

    from .contract import expand_home

    reached = {expand_home(value) for value in seen_static | observed_values}
    unused = []
    for section in ("exec", "load"):
        for entry in contract.sections[section]:
            if expand_home(entry.value) not in reached and entry.value != contract.program:
                unused.append({"section": section, "value": entry.value})
    return {"breaches": breaches, "unused": unused, "changed": changed}


def _capability_breaches(section, entry):
    """What a pinned [exec]/[load] file is able to do now and its contract entry does not list."""

    from .contract import expand_home
    from .profile import CLASSES, profile

    if not entry.attrs:
        return []
    path = expand_home(entry.value)
    try:
        data = profile(path)
    except OSError:
        return []
    if data.get("kind") != "elf":
        return []
    out = []
    pinned = entry.attr("caps")
    if pinned is not None:
        allowed = set() if pinned == "-" else set(pinned.split(","))
        for cls, symbols in sorted((data.get("classes") or {}).items()):
            if cls not in allowed and cls in CLASSES:
                out.append({"section": section, "value": path, "how": "static",
                            "detail": f"the file now uses {cls} ({', '.join(symbols)}); its entry allows caps={pinned}"})
    for key, field, label in (("ifuncs", "ifuncs", "IFUNC resolvers"), ("ctors", "constructors", "constructors run before main")):
        pinned_count = entry.attr(key)
        if pinned_count is not None and (data.get(field) or 0) > int(pinned_count):
            out.append({"section": section, "value": path, "how": "static",
                        "detail": f"{label}: {data.get(field)} now, the entry allows {key}={pinned_count}"})
    return out


def _check(options, workload):
    from .evidence import build_evidence_graph

    contract = load_contract(options.contract)
    if not Path(contract.program).exists():
        raise CLIError(f"the contract's program does not exist: {contract.program}")
    graph = build_evidence_graph(contract.program, max_depth=options.depth, max_files=options.limit, packages=False)
    observed = None
    if options.trace:
        from .observe import observe_run

        observed = observe_run([contract.program, *(workload or [])], timeout=options.timeout)
    elif workload:
        raise CLIError("arguments after -- are for --trace")
    result = check_contract(contract, graph, observed, strict=options.strict)
    if options.json:
        print(json.dumps({"schema_version": 1, "contract": options.contract, "program": contract.program,
                          "traced": observed is not None, **result}, indent=2))
    else:
        print("\n".join(_check_lines(contract, result, observed is not None)))
    return 1 if result["breaches"] else 0


def _check_lines(contract, result, traced):
    lines = [f"Contract for {contract.program}"]
    if result["changed"]:
        lines.append("  the program file changed since the contract was written (sha256 differs)")
    if not result["breaches"]:
        what = "its static evidence and the traced run stay" if traced else "its static evidence stays"
        lines.append(f"  OK: {what} within the contract")
        if not traced:
            lines.append("  (add --trace -- ARGS to also check what a real run reads, writes and connects to)")
    else:
        lines.append(f"  BREACH: {len(result['breaches'])} thing(s) the contract does not allow")
        for item in result["breaches"]:
            lines.append(f"    {item['section']:<6} {item['value']}")
            lines.append(f"           {item['how']}: {item['detail']}")
            for step in item.get("chain", []):
                evidence = step["evidence"][0]
                where = f"  ({evidence['file']}:{evidence['line']})" if evidence.get("file") and evidence.get("line") else ""
                lines.append(f"             └─ {step['kind']} [{step['basis']}] {evidence['detail']}{where}")
    if result["unused"]:
        lines.append(f"  {len(result['unused'])} [exec]/[load] entries are no longer reached (could be removed):")
        for item in result["unused"][:10]:
            lines.append(f"    {item['section']:<6} {item['value']}")
    return lines


# -- enforce -------------------------------------------------------------------

def _enforce(options, workload):
    from .enforce import enforce_command, landlock_rules, run_enforced

    contract = load_contract(options.contract)
    args = workload or []
    if options.dry_run:
        rules = landlock_rules(contract, extra_read=options.read, extra_write=options.write)
        print(json.dumps({"landlock": rules, "command": enforce_command(contract, args, "RULES.json")}, indent=2))
        return 0
    completed = run_enforced(contract, args, extra_read=options.read, extra_write=options.write)
    return completed.returncode


# -- minimize --------------------------------------------------------------------

def _required_by_loader(entry):
    return entry.comment.startswith(("declared: DT_NEEDED", "declared: PT_INTERP", "observed; declared: DT_NEEDED",
                                     "observed; declared: PT_INTERP"))


def _loader_closure(programs):
    """Files the dynamic loader maps for these programs: interpreters and DT_NEEDED, transitively."""

    from .elfscan import scan_elf
    from .libresolve import ldconfig_entries, resolve_library

    entries = ldconfig_entries()
    needed = set()
    queue = [os.path.realpath(path) for path in programs if os.path.exists(path)]
    while queue:
        path = queue.pop()
        if path in needed:
            continue
        needed.add(path)
        scan = scan_elf(path)
        if scan.interpreter and os.path.exists(scan.interpreter):
            queue.append(os.path.realpath(scan.interpreter))
        for soname in scan.needed:
            found = resolve_library(soname, Path(path).parent, scan.rpath, scan.runpath, (), scan.elf_class,
                                    scan.nodeflib, entries)
            if found.path is not None:
                queue.append(str(found.path))
    return needed


def _candidates(contract, everything):
    out = []
    for section in ("exec", "load", "read", "write", "net"):
        for entry in contract.sections[section]:
            if section == "exec" and entry.value == contract.program:
                continue
            if not everything and section == "load" and _required_by_loader(entry):
                continue
            out.append((section, entry))
    return out


def _with_only(contract, candidates, kept):
    trial = Contract(contract.program, contract.sha256, contract.package, contract.generated, contract.workload)
    kept_ids = {id(entry) for _, entry in kept}
    candidate_ids = {id(entry) for _, entry in candidates}
    for section in contract.sections:
        for entry in contract.sections[section]:
            if id(entry) not in candidate_ids or id(entry) in kept_ids:
                trial.sections[section].append(entry)
    return trial


def read_workloads(path):
    """Argument lists from a workloads file: one shell-quoted command line per line, # comments."""

    workloads = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise CLIError(f"cannot read {path}: {error.strerror}") from None
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                workloads.append(shlex.split(line))
            except ValueError as error:
                raise CLIError(f"{path}: {error}: {line}") from None
    if not workloads:
        raise CLIError(f"{path} lists no workloads")
    return workloads


def minimize(contract, args, max_runs=200, timeout=30, everything=False, same_stderr=True, run=None, workloads=None):
    """Remove every entry the workload does not need (delta debugging over entries).

    Returns (minimal contract, removed [(section, entry)], runs, baseline).
    A trial passes when the exit status, stdout and (with same_stderr,
    the default) stderr match a run under the full contract. Declared
    libraries of programs that were removed are dropped afterwards.
    """

    from .enforce import run_enforced

    argument_sets = workloads or [args]

    def run_one(trial, arguments):
        try:
            done = run_enforced(trial, arguments, capture=True, timeout=timeout, stdin=None)
        except (subprocess.TimeoutExpired, OSError) as error:  # counts as a different result
            return ("error", str(type(error).__name__))
        return (done.returncode, done.stdout, done.stderr if same_stderr else b"")

    def default_run(trial):
        # every workload must keep its result: an entry any workload needs is required
        return tuple(run_one(trial, arguments) for arguments in argument_sets)

    run = run or default_run
    runs = [0]
    baseline = run(contract)
    runs[0] += 1
    candidates = _candidates(contract, everything)

    def passes(kept):
        if runs[0] >= max_runs:
            return False
        runs[0] += 1
        return run(_with_only(contract, candidates, kept)) == baseline

    kept = list(candidates)
    if candidates and passes([]):
        kept = []
    granularity = 2
    while len(kept) >= 2 and runs[0] < max_runs:
        size = max(1, len(kept) // granularity)
        chunks = [kept[start:start + size] for start in range(0, len(kept), size)]
        reduced = False
        for index in range(len(chunks)):
            complement = [item for number, chunk in enumerate(chunks) if number != index for item in chunk]
            if passes(complement):
                kept = complement
                granularity = max(granularity - 1, 2)
                reduced = True
                break
        if not reduced:
            if granularity >= len(kept):
                break
            granularity = min(granularity * 2, len(kept))
    if len(kept) == 1 and passes([]):
        kept = []

    minimal = _with_only(contract, candidates, kept)
    kept_ids = {id(entry) for _, entry in kept}
    if not everything:
        needed = _loader_closure(minimal.values("exec"))
        for entry in list(minimal.sections["load"]):
            if _required_by_loader(entry) and os.path.realpath(entry.value) not in needed:
                minimal.sections["load"].remove(entry)
                candidates.append(("load", entry))
    for section in minimal.sections:
        minimal.sections[section] = [
            Entry(entry.value, f"required: {entry.comment}" if id(entry) in kept_ids else entry.comment, entry.attrs)
            for entry in minimal.sections[section]
        ]
    removed = [(section, entry) for section, entry in candidates if id(entry) not in kept_ids]
    return minimal, removed, runs[0], baseline


def _minimize(options, workload):
    contract = load_contract(options.contract)
    args = workload or []
    workloads = read_workloads(options.workloads) if options.workloads else None
    if workloads and args:
        raise CLIError("use either --workloads FILE or -- ARGS")
    minimal, removed, runs, _baseline = minimize(
        contract, args, max_runs=options.max_runs, timeout=options.timeout,
        everything=options.all, same_stderr=not options.ignore_stderr, workloads=workloads,
    )
    name = Path(contract.program).name
    minimal.workload = (f"{len(workloads)} workloads (listed below)" if workloads
                        else shlex.join([name, *args]))
    minimal.notes = [note for note in contract.notes]
    minimal.notes.append(
        f"minimized with {runs} enforced runs: every entry marked 'required' changed the result "
        f"(exit status and output) of the workload when removed"
    )
    if runs >= options.max_runs:
        minimal.notes.append(f"stopped at --max-runs {options.max_runs}: the result may not be minimal")
    for arguments in workloads or []:
        minimal.notes.append(f"workload `{shlex.join([name, *arguments])}`")
    for section, entry in removed:
        minimal.notes.append(f"removed, not needed for the workload: [{section}] {entry.value}")
    _write(minimal, options.output)
    print(f"{len(removed)} of {len(removed) + sum(1 for s in minimal.sections.values() for e in s if e.comment.startswith('required'))} "
          f"candidate entries removed in {runs} runs", file=sys.stderr)
    return 0
