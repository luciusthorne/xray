from pathlib import Path

from .analyze import analyze_python
from .analyzers import Analyzer, registry
from .graph import DependencyGraph
from .model import Edge
from .references import find_references
from .relationships import find_relationships
from .symbols import extract_symbols


def _location(path, root):
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _add(found, edge):
    if edge not in found:
        found.append(edge)


class PythonAnalyzer(Analyzer):
    """Reads Python files through the existing analysis functions.

    Import edges use DependencyGraph.resolve_import, so they agree
    with the dependency graph. For calls, inherits and references,
    the target is "path:name" when resolved and the name as written
    otherwise.
    """

    name = "python"
    kinds = ("python",)

    def symbols(self, path):
        return extract_symbols(path)

    def edges(self, path, project_root=None):
        path = Path(path).resolve()
        root = (
            Path(project_root).resolve()
            if project_root is not None
            else path.parent
        )
        location = _location(path, root)
        graph = DependencyGraph()
        found = []

        analysis = analyze_python(path, root)

        for dependency in analysis["dependencies"]:
            kind = dependency["type"]

            if kind in ("stdlib", "third-party"):
                edge = Edge(
                    str(path),
                    dependency["module"],
                    "imports",
                    "external",
                )
            elif kind == "local":
                target = graph.resolve_import(
                    dependency["module"],
                    dependency["name"],
                    root,
                    path,
                )

                if target is None:
                    edge = Edge(str(path), None, "imports", "unresolved")
                else:
                    edge = Edge(
                        str(path),
                        str(Path(target).resolve()),
                        "imports",
                        "resolved",
                    )
            else:
                continue

            _add(found, edge)

        for relationship in find_relationships(path, root):
            target = (
                relationship.target
                if relationship.status == "resolved"
                else relationship.name
            )

            _add(
                found,
                Edge(
                    f"{location}:{relationship.source}",
                    target,
                    relationship.kind,
                    relationship.status,
                ),
            )

        for reference in find_references(path, root):
            target = (
                reference.target
                if reference.status == "resolved"
                else reference.name
            )

            _add(
                found,
                Edge(location, target, "references", reference.status),
            )

        return found


if "python" not in registry.names():
    registry.register(PythonAnalyzer())
