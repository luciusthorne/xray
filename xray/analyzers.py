from .entrypoints import command_kind


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

    def symbols(self, path):
        return []


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
