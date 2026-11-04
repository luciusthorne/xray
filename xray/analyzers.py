from pathlib import Path

from .entrypoints import command_kind
from .model import LANGUAGE_NAMES, AnalysisDocument, FileInfo


class Analyzer:
    """Reads one kind of file and reports what it contains.

    kinds lists the command_kind values the analyzer handles. edges
    returns model.Edge records and symbols returns symbols.Symbol
    records. Both default to empty.
    """

    name = ""
    kinds = ()

    def can_handle(self, path):
        return command_kind(path) in self.kinds

    def edges(self, path):
        return []

    def command_edges(self, path):
        """Edges used when following an installed command into its code."""

        return self.edges(path)

    def project_edges(self, path, project_root):
        """Return relationships to consider in a whole-project graph."""
        return self.edges(path)

    def symbols(self, path):
        return []

    def analyze(self, path):
        """Return symbols and relationships in XRAY's common result model."""

        path = Path(path).resolve()
        kind = command_kind(path)
        return AnalysisDocument(
            file=FileInfo(str(path), kind, LANGUAGE_NAMES.get(kind)),
            analyzer=self.name,
            symbols=tuple(self.symbols(path)),
            relationships=tuple(self.edges(path)),
        )


class Registry:
    """An ordered set of analyzers. The first one that can handle a file wins."""

    def __init__(self):
        self._analyzers = []

    def register(self, analyzer):
        if not analyzer.name:
            raise ValueError("Analyzer needs a name")

        if analyzer.name in self.names():
            raise ValueError(
                f"Analyzer already registered: {analyzer.name}"
            )

        self._analyzers.append(analyzer)

    def analyzer_for(self, path):
        for analyzer in self._analyzers:
            if analyzer.can_handle(path):
                return analyzer

        return None

    def names(self):
        return [analyzer.name for analyzer in self._analyzers]


registry = Registry()


def load_builtin_analyzers():
    """Import built-in analyzers so registry consumers see the full set."""
    from . import (
        command_analyzers,  # noqa: F401
        javascript_analyzer,  # noqa: F401
        python_analyzer,  # noqa: F401
        ruby_analyzer,  # noqa: F401
        treesitter_analyzers,  # noqa: F401
    )


def analyzer_for(path):
    """Return the registered built-in analyzer for a file, if supported."""
    load_builtin_analyzers()
    return registry.analyzer_for(path)
