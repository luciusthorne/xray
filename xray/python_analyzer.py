from pathlib import Path

from .analyze import analyze_python
from .analyzers import Analyzer, registry
from .entrypoints import import_files
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

    def command_edges(self, path):
        """Resolve imports to files for launcher and command-chain views.

        Project dependency edges intentionally keep standard-library and
        third-party modules external. Command inspection follows installed
        module files so users can read what a launcher enters.
        """

        path = Path(path).resolve()
        found = []

        for target in import_files(path):
            target = target.resolve()
            name = target.name

            if name == "__init__.py":
                name = f"{target.parent.name}/__init__.py"

            found.append(
                Edge(str(path), str(target), "imports", "resolved", name=name)
            )

        return found

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
                    name=dependency["module"],
                )
            elif kind == "local":
                target = graph.resolve_import(
                    dependency["module"],
                    dependency["name"],
                    root,
                    path,
                )

                if target is None:
                    module = dependency["module"]
                    name = dependency["name"]
                    if module and name:
                        separator = "" if module.endswith(".") else "."
                        written = f"{module}{separator}{name}"
                    else:
                        written = module or name
                    edge = Edge(
                        str(path), None, "imports", "unresolved", name=written
                    )
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

    def project_edges(self, path, project_root):
        return self.edges(path, project_root)


if "python" not in registry.names():
    registry.register(PythonAnalyzer())
