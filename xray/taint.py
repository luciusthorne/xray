"""Cross-language taint: untrusted input followed from program to program.

The analysis starts at a command with its arguments, standard input,
the network and the environment as sources. Shell scripts and Python
files are read (xray.shtaint, xray.pytaint). When a file passes tainted
data to another program as arguments, or exports a tainted variable to
it, that program is analysed in turn with only those inputs tainted:
a script's $1 that a Python helper receives as sys.argv and hands to a
shell is one finding with a chain through both files. A compiled
program that receives tainted arguments is reported with what its
capability profile says it can do (start programs, run a shell): the
data flow inside machine code is not followed.

Every finding is inferred from code and is a lead to review, not proof
of a vulnerability: values may be validated in ways the analysis does
not model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .entrypoints import command_kind
from .locate import locate
from .shellscan import SHELLS


@dataclass
class TaintReport:
    root: str
    findings: list = field(default_factory=list)
    followed: list = field(default_factory=list)  # (file, kind, inputs)
    blind_spots: list = field(default_factory=list)


CODE_SINKS = ("command", "eval", "sh -c", "source", "trap", "shell", "exec", "compile", "pickle", "marshal",
              "yaml.load")
LEVELS = ("high", "medium", "low", "info")


def severity(sink, sources, privileged=False):
    """How much a finding matters, by trust boundary.

    Network input reaching code is high anywhere. Input to a setuid or
    setgid program is high, since its caller is less privileged. A
    command line tool's own arguments come from the user running it:
    arguments or stdin reaching eval or a shell is medium (quoting bugs,
    or a caller passing untrusted data), and a program that runs the
    command it was given ("$@") is doing its job (info). Environment
    alone is low.
    """

    kinds = {source.split(":")[0] for source in sources}
    if sink == "binary":
        return "medium" if "network" in kinds else "low"
    if sink not in CODE_SINKS:
        return "high" if "network" in kinds else "low"
    if "network" in kinds or (privileged and kinds):
        return "high"
    if sink == "command" and kinds <= {"argv", "env"}:
        return "info"
    if kinds & {"argv", "stdin"}:
        return "medium"
    return "low"


def _flat(argv_labels):
    out = set()
    for item in argv_labels:
        out |= set(item) if isinstance(item, (list, tuple, set)) else {item}
    return out


def _resolve(name, caller):
    if "/" in name:
        path = Path(name) if Path(name).is_absolute() else Path(caller).parent / name
        return str(path.resolve()) if path.is_file() else None
    found = locate(name)
    return str(Path(found).resolve()) if found else None


def analyze(command, argv=True, env=True, max_depth=4, max_files=50):
    """Return a TaintReport for a command name or path."""

    from .profile import profile
    from .pytaint import python_taint
    from .shtaint import shell_taint

    root = _resolve(command, ".") if "/" not in str(command) else str(Path(command).resolve())
    if root is None or not Path(root).exists():
        raise FileNotFoundError(command)
    report = TaintReport(root)
    info = Path(root).stat()
    privileged = bool(info.st_mode & 0o6000) and info.st_uid == 0
    queue = [(root, ["argv"] if argv else [], {}, env, [], 0)]
    seen = set()
    while queue and len(report.followed) < max_files:
        path, argv_labels, env_labels, env_default, chain, depth = queue.pop(0)
        argv_key = tuple(tuple(sorted(item)) if isinstance(item, (list, tuple, set)) else item for item in argv_labels)
        key = (path, argv_key, tuple(sorted((k, tuple(sorted(v))) for k, v in env_labels.items())))
        if key in seen:
            continue
        seen.add(key)
        kind = command_kind(path)
        if kind == "shell":
            result = shell_taint(path, argv_labels, env_labels, env_default)
            findings, calls, exported = result.findings, result.calls, result.exported
        elif kind == "python":
            findings, calls = python_taint(path, argv_labels, env_labels, env_default)
            exported = {}
        elif kind == "elf":
            from .elftaint import leads as elf_leads

            found, _how = elf_leads(path, limit=10) if (chain or path == root) else ([], None)
            labels = sorted(_flat(argv_labels) | {label for values in env_labels.values() for label in values})
            for lead in found:
                via = f" via {' -> '.join(lead.via)}" if lead.via else ""
                sources = sorted(set(labels) | {lead.kind if lead.kind != "input" else "stdin"})
                report.findings.append({
                    "file": path, "line": None, "sink": "binary",
                    "detail": f"in {lead.function}, {lead.source.symbol}() is followed by {lead.sink.symbol}(){via}"
                              f" (input at {lead.source.location or hex(lead.source.address)},"
                              f" sink at {lead.sink.location or hex(lead.sink.address)})",
                    "sources": sources, "expression": None, "chain": chain,
                    "severity": "medium" if lead.kind == "network" else "low", "basis": "guessed",
                })
            if chain and not found:
                data = profile(path)
                classes = data.get("classes") or {}
                able = [cls for cls in ("shell", "exec", "dynload") if cls in classes]
                if able:
                    labels = sorted(_flat(argv_labels) | {label for values in env_labels.values() for label in values})
                    report.findings.append({
                        "file": path, "line": None, "sink": "binary",
                        "detail": "a compiled program receives input and can "
                                  + ", ".join({"shell": "run a shell", "exec": "start programs",
                                               "dynload": "load code at run time"}[cls] for cls in able)
                                  + f" ({', '.join(sorted({symbol for cls in able for symbol in classes[cls]}))})",
                        "sources": labels, "expression": None, "chain": chain,
                        "severity": severity("binary", labels), "basis": "guessed",
                    })
            report.followed.append((path, kind, sorted(_flat(argv_labels))))
            continue
        else:
            report.blind_spots.append(f"{path}: {kind} files are not analysed for taint")
            continue
        report.followed.append((path, kind, sorted(_flat(argv_labels)) + sorted(env_labels)))
        for item in findings:
            item["chain"] = chain
            item["severity"] = severity(item["sink"], item["sources"], privileged)
            item["basis"] = "inferred"
            report.findings.append(item)
        if depth >= max_depth:
            continue
        for name, per_argument, line in calls:
            target = _resolve(name, path)
            if target is None or target == path:
                continue
            arguments = per_argument
            if Path(name).name in SHELLS or Path(target).name in ("python", "python3", "perl", "ruby", "node"):
                # an interpreter: the first non-option argument is the program it runs
                continue
            labels = sorted({label for values in arguments for label in values})
            tainted = [str(position) for position, values in enumerate(arguments, 1) if values]
            step = {"file": path, "line": line,
                    "detail": f"passes input to {Path(target).name} as argument {', '.join(tainted)} ({', '.join(labels)})"}
            positional = [list(values) for values in arguments]  # $1 / sys.argv[1] get exactly what was passed there
            queue.append((target, positional, {}, False, [*chain, step], depth + 1))
        if exported:
            for name, per_argument, line in calls:
                target = _resolve(name, path)
                if target and target != path:
                    step = {"file": path, "line": line,
                            "detail": f"exports {', '.join(sorted(exported))} to {Path(target).name}"}
                    queue.append((target, [], {key: set(value) for key, value in exported.items()}, False,
                                  [*chain, step], depth + 1))
    merged = {}
    for item in report.findings:
        key = (item["file"], item["line"], item["sink"], item["detail"] if item["line"] is None else "")
        if key not in merged:
            merged[key] = item
            continue
        kept = merged[key]
        kept["sources"] = sorted(set(kept["sources"]) | set(item["sources"]))
        if len(item["chain"]) < len(kept["chain"]):
            kept["chain"] = item["chain"]
        kept["severity"] = severity(kept["sink"], kept["sources"], privileged)
    report.findings = list(merged.values())
    order = {level: rank for rank, level in enumerate(LEVELS)}
    report.findings.sort(key=lambda item: (order[item["severity"]], len(item["chain"]), item["file"], item["line"] or 0))
    return report


def report_lines(report, show_low=False):
    findings = [item for item in report.findings if show_low or item["severity"] in ("high", "medium")]
    hidden = len(report.findings) - len(findings)
    lines = [f"Taint analysis of {report.root}",
             f"Followed {len(report.followed)} file(s) from the command's inputs: arguments, stdin, the network, the environment",
             ""]
    if not findings:
        lines.append("No path from input to code or command execution was found.")
    for item in findings:
        where = f"{item['file']}:{item['line']}" if item["line"] else item["file"]
        lines.append(f"[{item['severity']}] {item['detail']}")
        lines.append(f"    at {where}   from: {', '.join(item['sources'])}   ({item['basis']})")
        if item.get("expression"):
            lines.append(f"    expression: {item['expression']}")
        for step in item["chain"]:
            lines.append(f"    via {step['file']}:{step['line']}: {step['detail']}")
        lines.append("")
    if hidden:
        lines.append(f"{hidden} low or info finding(s) hidden (--all): environment-only input, unquoted arguments,"
                     " or a program running the command it was given")
    for spot in report.blind_spots[:10]:
        lines.append(f"blind spot: {spot}")
    lines.append("Findings are leads inferred from code, not proof: input may be validated in ways not modelled.")
    return lines


def scan_scripts(directories=None, limit=None, progress=None):
    """Analyse every shell and Python command in the PATH directories; return [(command, TaintReport)]."""

    from .evidencestore import path_dirs
    from .scan import commands_in

    commands = commands_in(directories or path_dirs())
    chosen = [(name, path) for name, path in sorted(commands.items()) if command_kind(path) in ("shell", "python")]
    if limit:
        chosen = chosen[:limit]
    out = []
    for number, (name, path) in enumerate(chosen, 1):
        if progress:
            progress(number, len(chosen), name)
        try:
            out.append((name, analyze(path, max_depth=2, max_files=20)))
        except (OSError, RecursionError, ValueError):
            continue
    return out
