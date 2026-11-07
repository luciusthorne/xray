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


PLUGIN_GROUP = "xray.analyzers"
SCRIPT_KINDS = frozenset({"ruby", "javascript", "lua", "typescript", "c", "lisp"})  # analyzer-backed kinds
_plugins = {"done": False, "loaded": [], "failed": [], "analyzers": []}


def load_plugins():
    """Register analyzers other packages offer under the `xray.analyzers` entry point group.

    An entry point may name an Analyzer instance, an Analyzer subclass, or a
    callable returning one. It needs a `name` and `kinds`; a `claims(path)`
    method lets it take files XRAY does not otherwise recognise. A plugin that
    fails to load is recorded and skipped; it never stops XRAY.
    """

    if _plugins["done"]:
        return
    _plugins["done"] = True
    from importlib.metadata import entry_points

    try:
        points = list(entry_points(group=PLUGIN_GROUP))
    except Exception as error:  # noqa: BLE001 - a broken environment must not stop XRAY
        _plugins["failed"].append(("(entry points)", f"{type(error).__name__}: {error}"))
        return
    for point in points:
        try:
            target = point.load()
            analyzer = target() if isinstance(target, type) or (callable(target) and not isinstance(target, Analyzer)) else target
            if not getattr(analyzer, "name", "") or not getattr(analyzer, "kinds", ()):
                raise ValueError("an analyzer needs a name and kinds")
            if analyzer.name in registry.names():
                raise ValueError(f"the name {analyzer.name!r} is already taken")
            builtin_kinds = {"elf", "python", "shell", "perl", "script", "unknown"} | SCRIPT_KINDS
            clash = [kind for kind in analyzer.kinds if kind in builtin_kinds]
            if clash:
                raise ValueError(f"kinds {clash} belong to built-in analyzers")
            registry.register(analyzer)
            _plugins["analyzers"].append(analyzer)
            dist = getattr(getattr(point, "dist", None), "name", None)
            _plugins["loaded"].append((point.name, analyzer.name, tuple(analyzer.kinds), dist))
        except Exception as error:  # noqa: BLE001 - plugins are other people's code
            _plugins["failed"].append((point.name, f"{type(error).__name__}: {error}"))


def plugin_report():
    """(loaded, failed) for `xray plugins`."""

    load_builtin_analyzers()
    return list(_plugins["loaded"]), list(_plugins["failed"])


def plugin_kinds():
    load_builtin_analyzers()
    return {kind for analyzer in _plugins["analyzers"] for kind in analyzer.kinds}


def script_kinds():
    """Kinds read through an analyzer's symbols and edges: built-in ones and plugins'."""

    return SCRIPT_KINDS | plugin_kinds()


def plugin_kind_for(path):
    """The kind a plugin claims for path, or None."""

    load_builtin_analyzers()
    for analyzer in _plugins["analyzers"]:
        claims = getattr(analyzer, "claims", None)
        try:
            if claims is not None and claims(Path(path)):
                return analyzer.kinds[0]
        except Exception:  # noqa: BLE001, S112 - a plugin's claims() failing means "not mine"
            continue
    return None


def language_name(kind):
    for analyzer in _plugins["analyzers"]:
        if kind in analyzer.kinds:
            return getattr(analyzer, "language", None) or kind.title()
    return LANGUAGE_NAMES.get(kind, kind.title())


def load_builtin_analyzers():
    """Import built-in analyzers so registry consumers see the full set."""
    from . import (
        command_analyzers,  # noqa: F401
        javascript_analyzer,  # noqa: F401
        lisp,  # noqa: F401
        python_analyzer,  # noqa: F401
        ruby_analyzer,  # noqa: F401
        treesitter_analyzers,  # noqa: F401
    )

    load_plugins()


def analyzer_for(path):
    """Return the registered built-in analyzer for a file, if supported."""
    load_builtin_analyzers()
    return registry.analyzer_for(path)
