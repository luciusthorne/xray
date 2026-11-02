"""Whole-project dependency graphs backed by the analyzer registry."""

import os
import subprocess
from pathlib import Path

from .analyzers import analyzer_for
from .errors import XRAYError
from .graph import DependencyGraph

SKIPPED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", "target", "build", "dist", ".mypy_cache",
    ".pytest_cache", ".ruff_cache",
}
PROJECT_EDGE_KINDS = {"imports", "sources", "runs"}


def build_project_graph(project_root, workspace_root):
    """Index supported files and their resolved in-project relationships."""
    root = Path(project_root).resolve()
    workspace = Path(workspace_root).resolve()
    graph = DependencyGraph()
    analyzers = {}

    for folder, dirs, filenames in os.walk(root):
        dirs[:] = sorted(
            name for name in dirs
            if name not in SKIPPED_DIRS and not name.startswith(".")
        )

        for filename in sorted(filenames):
            candidate = Path(folder) / filename
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if root not in resolved.parents:
                continue
            try:
                node = resolved.relative_to(workspace).as_posix()
            except ValueError:
                continue
            analyzer = analyzer_for(resolved)
            if analyzer is None:
                continue
            graph.add_node(node)
            analyzers[resolved] = (node, analyzer)

    for path, (source, analyzer) in sorted(analyzers.items()):
        try:
            edges = analyzer.project_edges(path, root)
        except (OSError, SyntaxError, ValueError, subprocess.SubprocessError, XRAYError):
            continue

        for edge in edges:
            if edge.kind not in PROJECT_EDGE_KINDS:
                continue
            if edge.status in {"external", "unresolved"}:
                name = edge.name or edge.target or "(unknown)"
                item = (source, edge.kind, name)
                collection = (
                    graph.external_edges
                    if edge.status == "external"
                    else graph.unresolved_edges
                )
                if item not in collection:
                    collection.append(item)
                continue
            if edge.status != "resolved":
                continue
            if not edge.target:
                continue
            target = Path(edge.target)
            # Python relationships can name symbols as "file.py:function";
            # file dependencies must resolve to an actual indexed source file.
            if not target.is_file():
                continue
            target = target.resolve()
            target_node = analyzers.get(target)
            if target_node is None:
                continue
            graph.add_edge(source, target_node[0])

    return graph
