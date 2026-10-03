from pathlib import Path

from .errors import XRAYError
from .relationships import find_relationships


class CallGraph:
    """Static call relationships between functions, methods, classes.

    Nodes are "relative/path.py:qualified.name" strings. Only calls
    that resolve to a definition become edges. Calls that cannot be
    resolved are kept separately and never guessed.
    """

    def __init__(self):
        self.nodes = set()
        self.edges = []
        self._unresolved = []

    def add_call(self, caller, callee):
        self.nodes.add(caller)
        self.nodes.add(callee)

        edge = (caller, callee)

        if edge not in self.edges:
            self.edges.append(edge)

    def add_unresolved(self, caller, name, status):
        self.nodes.add(caller)

        item = (caller, name, status)

        if item not in self._unresolved:
            self._unresolved.append(item)

    def callees_of(self, node):
        return sorted(
            callee
            for caller, callee in self.edges
            if caller == node
        )

    def callers_of(self, node):
        return sorted(
            caller
            for caller, callee in self.edges
            if callee == node
        )

    def unresolved_from(self, node):
        return sorted(
            (name, status)
            for caller, name, status in self._unresolved
            if caller == node
        )

    def reachable_from(self, node):
        seen = set()
        stack = [node]

        while stack:
            current = stack.pop()

            for callee in self.callees_of(current):
                if callee != node and callee not in seen:
                    seen.add(callee)
                    stack.append(callee)

        return sorted(seen)


def build_call_graph(project_root):
    """Build a call graph from every Python file under project_root.

    Files that cannot be read or parsed are skipped.
    """

    project_root = Path(project_root).resolve()
    graph = CallGraph()

    for path in sorted(project_root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue

        try:
            relationships = find_relationships(path, project_root)
        except XRAYError:
            continue

        location = path.relative_to(project_root).as_posix()

        for relationship in relationships:
            if relationship.kind != "calls":
                continue

            caller = f"{location}:{relationship.source}"

            if relationship.status == "resolved":
                graph.add_call(caller, relationship.target)
            else:
                graph.add_unresolved(
                    caller,
                    relationship.name,
                    relationship.status,
                )

    return graph
