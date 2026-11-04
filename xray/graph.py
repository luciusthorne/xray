from collections import deque
from pathlib import Path

from .errors import XRAYError


class DependencyGraph:
    def __init__(self):
        self.nodes = set()
        self.edges = []
        self.external_edges = []
        self.unresolved_edges = []

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

    # ------------------------------------------------------------------
    # Reachability
    # ------------------------------------------------------------------

    def reachable_from(self, node):
        if node not in self.nodes:
            return []

        reachable = set()
        queue = deque(
            sorted(self.dependencies_of(node))
        )

        while queue:
            current = queue.popleft()

            if current == node:
                continue

            if current in reachable:
                continue

            reachable.add(current)

            for dependency in sorted(
                self.dependencies_of(current)
            ):
                if dependency != node:
                    queue.append(dependency)

        return sorted(reachable)

    def reachable_count(self, node):
        return len(self.reachable_from(node))

    def reverse_reachable_from(self, node):
        visited = set()
        queue = deque([node])

        while queue:
            current = queue.popleft()

            for dependency in self.dependents_of(current):
                if dependency in visited:
                    continue

                visited.add(dependency)
                queue.append(dependency)

        return sorted(visited)

    def reverse_reachable_count(self, node):
        return len(self.reverse_reachable_from(node))

    def reachability_stats(self, node):
        return {
            "reachable": self.reachable_count(node),
            "reverse_reachable": self.reverse_reachable_count(node),
        }

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------

    def find_path(self, source, target):
        if source not in self.nodes:
            return []

        if target not in self.nodes:
            return []

        if source == target:
            return [source]

        queue = deque([source])
        previous = {source: None}

        while queue:
            current = queue.popleft()

            for dependency in sorted(
                self.dependencies_of(current)
            ):
                if dependency in previous:
                    continue

                previous[dependency] = current

                if dependency == target:
                    path = []
                    node = target

                    while node is not None:
                        path.append(node)
                        node = previous[node]

                    path.reverse()
                    return path

                queue.append(dependency)

        return []

    # ------------------------------------------------------------------
    # Strongly connected components / cycles
    # ------------------------------------------------------------------

    def strongly_connected_components(self):
        """
        Return strongly connected components using Tarjan's algorithm.

        Components are returned deterministically, with nodes sorted
        inside each component and components ordered by their first node.
        """

        index = 0
        indices = {}
        lowlinks = {}
        stack = []
        on_stack = set()
        components = []

        adjacency = {
            node: sorted(self.dependencies_of(node))
            for node in self.nodes
        }

        def strongconnect(node):
            nonlocal index

            indices[node] = index
            lowlinks[node] = index
            index += 1

            stack.append(node)
            on_stack.add(node)

            for dependency in adjacency[node]:
                if dependency not in indices:
                    strongconnect(dependency)

                    lowlinks[node] = min(
                        lowlinks[node],
                        lowlinks[dependency],
                    )

                elif dependency in on_stack:
                    lowlinks[node] = min(
                        lowlinks[node],
                        indices[dependency],
                    )

            if lowlinks[node] == indices[node]:
                component = []

                while True:
                    current = stack.pop()
                    on_stack.remove(current)
                    component.append(current)

                    if current == node:
                        break

                components.append(
                    sorted(component)
                )

        for node in sorted(self.nodes):
            if node not in indices:
                strongconnect(node)

        return sorted(
            components,
            key=lambda component: component[0],
        )

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

    # ------------------------------------------------------------------
    # Dependency analysis
    # ------------------------------------------------------------------

    def dependency_hotspots(self):
        counts = {}

        for source, target in self.edges:
            counts[target] = counts.get(target, 0) + 1

        return sorted(
            counts.items(),
            key=lambda item: (-item[1], item[0]),
        )

    def impact_of(self, node):
        direct = sorted(
            self.dependents_of(node)
        )

        indirect = set()

        queue = deque(direct)

        while queue:
            current = queue.popleft()

            for dependent in self.dependents_of(current):
                if dependent == node:
                    continue

                if dependent in direct:
                    continue

                if dependent in indirect:
                    continue

                indirect.add(dependent)
                queue.append(dependent)

        return {
            "direct": direct,
            "indirect": sorted(indirect),
        }

    def impact_chains(self, node):
        chains = []

        def walk(current, path, visited):
            dependents = sorted(
                self.dependents_of(current)
            )

            if not dependents:
                if len(path) > 1:
                    chains.append(path)
                return

            for dependent in dependents:
                new_path = path + [dependent]

                if dependent == node:
                    chains.append(new_path)
                    continue

                if dependent in visited:
                    continue

                walk(
                    dependent,
                    new_path,
                    visited | {dependent},
                )

        if node not in self.nodes:
            return []

        walk(
            node,
            [node],
            {node},
        )

        return sorted(chains)

    # ------------------------------------------------------------------
    # Import resolution
    # ------------------------------------------------------------------

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
        source_path=None,
    ):
        """
        Resolve a local Python import.

        Examples:

            from .cycle_b import hello_b
                -> cycle_b.py

            from . import database
                -> database.py

            from package import database
                -> package/database.py

            import package.database
                -> package/database.py
        """

        module = module.strip()

        # --------------------------------------------------------------
        # Relative imports
        # --------------------------------------------------------------

        if module.startswith("."):
            if source_path is None:
                return None

            level = len(module) - len(module.lstrip("."))
            module_name = module[level:]

            base = Path(source_path).resolve().parent

            # "." = current package
            # ".." = parent package
            for _ in range(level - 1):
                base = base.parent

            # ----------------------------------------------------------
            # from .cycle_b import hello_b
            #
            # The dependency is cycle_b.py.
            # "hello_b" is an imported symbol, NOT another module.
            # ----------------------------------------------------------

            if module_name:
                module_path = base.joinpath(
                    *module_name.split(".")
                )

                file_path = module_path.with_suffix(".py")

                if file_path.exists():
                    return str(file_path)

                package_init = module_path / "__init__.py"

                if package_init.exists():
                    return str(package_init)

                # ------------------------------------------------------
                # Fallback:
                #
                # from .package import database
                #
                # could mean package/database.py
                # ------------------------------------------------------

                if name:
                    candidate = module_path / name

                    file_path = candidate.with_suffix(".py")

                    if file_path.exists():
                        return str(file_path)

                    package_init = candidate / "__init__.py"

                    if package_init.exists():
                        return str(package_init)

                return None

            # ----------------------------------------------------------
            # from . import database
            # ----------------------------------------------------------

            if name:
                candidate = base / name

                file_path = candidate.with_suffix(".py")

                if file_path.exists():
                    return str(file_path)

                package_init = candidate / "__init__.py"

                if package_init.exists():
                    return str(package_init)

            package_init = base / "__init__.py"

            if package_init.exists():
                return str(package_init)

            return None

        # --------------------------------------------------------------
        # Absolute imports
        # --------------------------------------------------------------

        if not module:
            return None

        # For:
        #
        #     from package import database
        #
        # prefer:
        #
        #     package/database.py
        #
        # over:
        #
        #     package/__init__.py

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

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build_from(
        self,
        source,
        analyze_function,
        project_root,
        workspace_root,
    ):
        visited = set()

        project_root = Path(
            project_root
        ).resolve()

        workspace_root = Path(
            workspace_root
        ).resolve()

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
                    path,
                )

                if target is None:
                    continue

                target_path = Path(
                    target
                ).resolve()

                try:
                    target_node = str(
                        target_path.relative_to(
                            workspace_root
                        )
                    )
                except ValueError:
                    continue

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
        project_root = Path(
            project_root
        ).resolve()

        workspace_root = Path(
            workspace_root
        ).resolve()

        paths = sorted(
            project_root.rglob("*.py")
        )

        # First add every Python file as a node.
        for path in paths:
            if "__pycache__" in path.parts:
                continue

            try:
                source_node = str(
                    path.relative_to(
                        workspace_root
                    )
                )
            except ValueError:
                continue

            self.add_node(source_node)

        # Then add dependency edges.
        for path in paths:
            if "__pycache__" in path.parts:
                continue

            try:
                analysis = analyze_function(path)
            except (OSError, SyntaxError, XRAYError):
                continue

            try:
                source_node = str(
                    path.relative_to(
                        workspace_root
                    )
                )
            except ValueError:
                continue

            for dependency in analysis["dependencies"]:
                if dependency["type"] != "local":
                    continue

                target = self.resolve_import(
                    dependency["module"],
                    dependency["name"],
                    project_root,
                    path,
                )

                if target is None:
                    continue

                try:
                    target_node = str(
                        Path(target)
                        .resolve()
                        .relative_to(
                            workspace_root
                        )
                    )
                except ValueError:
                    continue

                self.add_edge(
                    source_node,
                    target_node,
                )

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def dependency_tree(self, node):
        if node not in self.nodes:
            return [node]

        lines = [node]

        def walk(current, prefix, visited):
            dependencies = sorted(
                self.dependencies_of(current)
            )

            for index, dependency in enumerate(
                dependencies
            ):
                is_last = (
                    index == len(dependencies) - 1
                )

                branch = (
                    "└── "
                    if is_last
                    else "├── "
                )

                lines.append(
                    prefix
                    + branch
                    + dependency
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

        walk(
            node,
            "",
            {node},
        )

        return lines
