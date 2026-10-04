from pathlib import Path

from . import command_analyzers, python_analyzer  # noqa: F401  (register analyzers)
from .analyzers import registry
from .entrypoints import command_kind


def export_data(path):
    """Return everything XRAY knows about one file as plain data.

    The analyzer is chosen by the file's kind through the registry.
    Files no analyzer handles give empty symbols and edges.
    """

    path = Path(path).resolve()
    analyzer = registry.analyzer_for(path)
    symbols = []
    edges = []

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

    return {
        "file": str(path),
        "kind": command_kind(path),
        "analyzer": analyzer.name if analyzer else None,
        "symbols": symbols,
        "edges": edges,
    }
