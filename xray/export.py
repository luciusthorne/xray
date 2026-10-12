from pathlib import Path

from . import command_analyzers, python_analyzer  # noqa: F401  (register analyzers)
from .analyzers import registry
from .entrypoints import command_kind
from .shellscan import scan_shell


def export_data(path):
    """Return everything XRAY knows about one file as plain data.

    The analyzer is chosen by the file's kind through the registry.
    Files no analyzer handles give empty symbols and edges.
    """

    path = Path(path).resolve()
    analyzer = registry.analyzer_for(path)
    symbols = []
    edges = []
    notes = []

    if analyzer is not None:
        symbols = [
            {
                "name": symbol.name,
                "kind": symbol.kind,
                "line": symbol.line,
                "parent": symbol.parent,
            }
            for symbol in analyzer.symbols(path)
        ]
        edges = [
            {
                "source": edge.source,
                "target": edge.target,
                "kind": edge.kind,
                "status": edge.status,
            }
            for edge in analyzer.edges(path)
        ]

    if analyzer is not None and analyzer.name == "shell":
        scan = scan_shell(path)

        if scan.dynamic:
            dynamic_note = (
                f"{scan.dynamic} command(s) run through variables or eval "
                "(not resolved)"
            )
        else:
            dynamic_note = None

        if not scan.commands:
            notes.append(
                "no external commands found by static reading "
                "(commands run through variables or eval are not visible)"
            )

        if dynamic_note:
            notes.append(dynamic_note)

    return {
        "file": str(path),
        "kind": command_kind(path),
        "analyzer": analyzer.name if analyzer else None,
        "symbols": symbols,
        "edges": edges,
        "notes": notes,
    }
