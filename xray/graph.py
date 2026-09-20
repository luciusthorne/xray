from collections import deque
from pathlib import Path


class DependencyGraph:
    def __init__(self):
        self.nodes = set()
        self.edges = []

    def add_node(self, node):
        self.nodes.add(node)

    def add_edge(self, source, target):
        self.nodes.add(source)
        self.nodes.add(target)

        edge = (source, target)

        if edge not in self.edges:
            self.edges.append(edge)

    def node_count(self):
        return len(self.nodes)

    def edge_count(self):
        return len(self.edges)

    def dependencies_of(self, node):
        return [
            target
            for source, target in self.edges
            if source == node
        ]

    def dependents_of(self, node):
        return [
            source
            for source, target in self.edges
            if target == node
        ]

    def leaf_nodes(self):
        return sorted(
            node
            for node in self.nodes
            if not self.dependencies_of(node)
        )

    def dependency_depth(self, node):
        def depth(current, visited):
            dependencies = self.dependencies_of(current)

            if not dependencies:
                return 0

            maximum = 0

            for dependency in dependencies:
                if dependency in visited:
                    continue

                maximum = max(
                    maximum,
                    1 + depth(
                        dependency,
                        visited | {dependency},
                    ),
                )

            return maximum

        if node not in self.nodes:
            return 0

        return depth(node, {node})

    def cycle_count(self):
        return sum(
            1
            for component in self.strongly_connected_components()
            if len(component) > 1
            or (
                len(component) == 1
                and (
                    component[0],
                    component[0],
                ) in self.edges
            )
        )

    def dependency_hotspots(self):
        counts = {}

        for source, target in self.edges:
            counts[target] = counts.get(target, 0) + 1

        return sorted(
            counts.items(),
            key=lambda item: (-item[1], item[0]),
        )

    def resolve_local_module(self, module, project_root):
        module = module.strip()

        if module.startswith("."):
            module = module.lstrip(".")

        if not module:
            return None

        parts = module.split(".")
        module_path = Path(project_root).joinpath(*parts)

        file_path = module_path.with_suffix(".py")

        if file_path.exists():
            return str(file_path)

        package_init = module_path / "__init__.py"

        if package_init.exists():
            return str(package_init)

        return None

    def resolve_import(
        self,
        module,
        name,
        project_root,
    ):
        """
        Resolve an import.

        For imports such as:

            from package import database

        prefer:

            package/database.py

        over:

            package/__init__.py
        """

        module = module.strip()

        if module.startswith("."):
            module = module.lstrip(".")

        if not module:
            return None

        if name:
            candidate_module = f"{module}.{name}"

            resolved = self.resolve_local_module(
                candidate_module,
                project_root,
            )

            if resolved is not None:
                return resolved

        return self.resolve_local_module(
            module,
            project_root,
        )

    def build_from(
        self,
        source,
        analyze_function,
        project_root,
        workspace_root,
    ):
        visited = set()

        def visit(path):
            path = Path(path).resolve()

            if path in visited:
                return

            visited.add(path)

            try:
                analysis = analyze_function(path)
            except (OSError, SyntaxError):
                return

            source_node = str(
                path.relative_to(workspace_root)
            )

            self.add_node(source_node)

            for dependency in analysis["dependencies"]:
                if dependency["type"] != "local":
                    continue

                target = self.resolve_import(
                    dependency["module"],
                    dependency["name"],
                    project_root,
                )

                if target is None:
                    continue

                target_path = Path(target).resolve()

                target_node = str(
                    target_path.relative_to(workspace_root)
                )

                self.add_edge(
                    source_node,
                    target_node,
                )

                visit(target_path)

        visit(source)

    def build_project(
        self,
        project_root,
        analyze_function,
        workspace_root,
    ):
        project_root = Path(project_root).resolve()
        workspace_root = Path(workspace_root).resolve()

        for path in project_root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue

            source_node = str(
                path.relative_to(workspace_root)
            )

            self.add_node(source_node)

        for path in project_root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue

            try:
                analysis = analyze_function(path)
            except (OSError, SyntaxError):
                continue

            source_node = str(
                path.relative_to(workspace_root)
            )

            for dependency in analysis["dependencies"]:
                if dependency["type"] != "local":
                    continue

                target = self.resolve_import(
                    dependency["module"],
                    dependency["name"],
                    project_root,
                )

                if target is None:
                    continue

                target_node = str(
                    Path(target)
                    .resolve()
                    .relative_to(workspace_root)
                )

                self.add_edge(
                    source_node,
                    target_node,
                )

    def dependency_tree(self, node):
        lines = [node]

        def walk(current, prefix, visited):
            dependencies = sorted(
                self.dependencies_of(current)
            )

            for index, dependency in enumerate(dependencies):
                is_last = index == len(dependencies) - 1

                branch = "└── " if is_last else "├── "

                lines.append(
                    prefix + branch + dependency
                )

                if dependency in visited:
                    continue

                visited.add(dependency)

                extension = (
                    "    "
                    if is_last
                    else "│   "
                )

                walk(
                    dependency,
                    prefix + extension,
                    visited,
                )

        walk(node, "", {node})

        return lines

    def impact_of(self, node):
        direct = sorted(
            self.dependents_of(node)
        )

        indirect = []
        visited = {node}

        def walk(current):
            for dependent in self.dependents_of(current):
                if dependent in visited:
                    continue

                visited.add(dependent)

                if dependent not in direct:
                    indirect.append(dependent)

                walk(dependent)

        for dependent in direct:
            visited.add(dependent)
            walk(dependent)

        return {
            "direct": direct,
            "indirect": sorted(indirect),
        }

    def impact_chains(self, node):
        chains = []

        def walk(current, path):
            dependents = sorted(
                self.dependents_of(current)
            )

            if not dependents:
                chains.append(path)
                return

            for dependent in dependents:
                if dependent in path:
                    chains.append(
                        path + [dependent]
                    )
                    continue

                walk(
                    dependent,
                    path + [dependent],
                )

        walk(node, [node])

        return chains

    def reachable_from(self, node):
        if node not in self.nodes:
            return []

        reachable = []
        visited = {node}
        queue = deque([node])

        while queue:
            current = queue.popleft()

            for dependency in sorted(
                self.dependencies_of(current)
            ):
                if dependency in visited:
                    continue

                visited.add(dependency)
                reachable.append(dependency)
                queue.append(dependency)

        return reachable

    def reverse_reachable_from(self, node):
        if node not in self.nodes:
            return []

        reachable = []
        visited = {node}
        queue = deque([node])

        while queue:
            current = queue.popleft()

            for dependent in sorted(
                self.dependents_of(current)
            ):
                if dependent in visited:
                    continue

                visited.add(dependent)
                reachable.append(dependent)
                queue.append(dependent)

        return sorted(reachable)

    def reachable_count(self, node):
        return len(
            self.reachable_from(node)
        )

    def reverse_reachable_count(self, node):
        return len(
            self.reverse_reachable_from(node)
        )

    def reachability_stats(self, node):
        return {
            "reachable": self.reachable_count(node),
            "reverse_reachable": (
                self.reverse_reachable_count(node)
            ),
        }

    def find_path(self, source, target):
        if source not in self.nodes:
            return []

        if target not in self.nodes:
            return []

        if source == target:
            return [source]

        queue = deque([source])
        parents = {source: None}

        while queue:
            current = queue.popleft()

            for neighbor in sorted(
                self.dependencies_of(current)
            ):
                if neighbor in parents:
                    continue

                parents[neighbor] = current

                if neighbor == target:
                    path = []
                    cursor = target

                    while cursor is not None:
                        path.append(cursor)
                        cursor = parents[cursor]

                    path.reverse()
                    return path

                queue.append(neighbor)

        return []

    def strongly_connected_components(self):
        """
        Find strongly connected components using
        Tarjan's algorithm.
        """

        index = 0
        indices = {}
        lowlinks = {}
        stack = []
        on_stack = set()
        components = []

        def strong_connect(node):
            nonlocal index

            indices[node] = index
            lowlinks[node] = index
            index += 1

            stack.append(node)
            on_stack.add(node)

            for neighbor in sorted(
                self.dependencies_of(node)
            ):
                if neighbor not in indices:
                    strong_connect(neighbor)

                    lowlinks[node] = min(
                        lowlinks[node],
                        lowlinks[neighbor],
                    )

                elif neighbor in on_stack:
                    lowlinks[node] = min(
                        lowlinks[node],
                        indices[neighbor],
                    )

            if lowlinks[node] == indices[node]:
                component = []

                while True:
                    neighbor = stack.pop()
                    on_stack.remove(neighbor)
                    component.append(neighbor)

                    if neighbor == node:
                        break

                components.append(
                    sorted(component)
                )

        for node in sorted(self.nodes):
            if node not in indices:
                strong_connect(node)

        return sorted(
            components,
            key=lambda component: component[0],
        )
