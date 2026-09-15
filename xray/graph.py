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

    def node_count(self):
        return len(self.nodes)

    def edge_count(self):
        return len(self.edges)

    def leaf_nodes(self):
        return sorted(
            node
            for node in self.nodes
            if not self.dependencies_of(node)
        )

    def most_depended_on(self):
        if not self.nodes:
            return None

        counts = {
            node: len(self.dependents_of(node))
            for node in self.nodes
        }

        max_count = max(counts.values())

        if max_count == 0:
            return None

        return sorted(
            node
            for node, count in counts.items()
            if count == max_count
        )

    def dependency_hotspots(self):
        hotspots = []

        for node in self.nodes:
            count = len(self.dependents_of(node))

            if count > 0:
                hotspots.append((node, count))

        return sorted(
            hotspots,
            key=lambda item: (-item[1], item[0]),
        )

    def cycle_count(self):
        return len(self.find_cycles())

    def resolve_local_module(
        self,
        module,
        project_root,
        name=None,
    ):
        module = module.lstrip(".")
        parts = module.split(".")

        module_path = Path(project_root).joinpath(*parts)

        if name:
            imported_module = module_path / f"{name}.py"

            if imported_module.exists():
                return str(imported_module)

            imported_package = (
                module_path
                / name
                / "__init__.py"
            )

            if imported_package.exists():
                return str(imported_package)

        file_path = module_path.with_suffix(".py")

        if file_path.exists():
            return str(file_path)

        package_init = module_path / "__init__.py"

        if package_init.exists():
            return str(package_init)

        return None

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

                dependency_root = (
                    path.parent
                    if dependency["relative"]
                    else project_root
                )

                target = self.resolve_local_module(
                    dependency["module"],
                    dependency_root,
                    dependency["name"],
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
                path.resolve().relative_to(workspace_root)
            )

            self.add_node(source_node)

        for path in project_root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue

            try:
                analysis = analyze_function(
                    path,
                    project_root,
                )
            except (OSError, SyntaxError):
                continue

            source_node = str(
                path.resolve().relative_to(workspace_root)
            )

            for dependency in analysis["dependencies"]:
                if dependency["type"] != "local":
                    continue

                dependency_root = (
                    path.parent
                    if dependency["relative"]
                    else project_root
                )

                target = self.resolve_local_module(
                    dependency["module"],
                    dependency_root,
                    dependency["name"],
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

                branch = (
                    "└── "
                    if is_last
                    else "├── "
                )

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

    def find_cycles(self):
        cycles = []
        seen = set()

        def canonical_cycle(cycle):
            cycle = cycle[:-1]

            rotations = []

            for index in range(len(cycle)):
                rotated = (
                    cycle[index:]
                    + cycle[:index]
                )

                rotations.append(tuple(rotated))

            return min(rotations)

        def walk(start, current, path):
            for dependency in sorted(
                self.dependencies_of(current)
            ):
                if dependency == start:
                    cycle = path + [start]
                    key = canonical_cycle(cycle)

                    if key not in seen:
                        seen.add(key)
                        cycles.append(list(key))

                elif dependency not in path:
                    walk(
                        start,
                        dependency,
                        path + [dependency],
                    )

        for node in sorted(self.nodes):
            walk(node, node, [node])

        return sorted(cycles)

    def dependency_depth(self, node):
        memo = {}
        visiting = set()

        def depth(current):
            if current in memo:
                return memo[current]

            if current in visiting:
                return 0

            visiting.add(current)

            dependencies = self.dependencies_of(current)

            if not dependencies:
                result = 0
            else:
                result = 1 + max(
                    depth(dependency)
                    for dependency in dependencies
                )

            visiting.remove(current)
            memo[current] = result

            return result

        return depth(node)

    def strongly_connected_components(self):
        index = 0
        indices = {}
        lowlinks = {}
        stack = []
        on_stack = set()
        components = []

        def visit(node):
            nonlocal index

            indices[node] = index
            lowlinks[node] = index
            index += 1

            stack.append(node)
            on_stack.add(node)

            for dependency in self.dependencies_of(node):
                if dependency not in indices:
                    visit(dependency)

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
                visit(node)

        return sorted(
            components,
            key=lambda component: component[0],
        )

    def reachable_from(self, node):
        reachable = set()
        visited = {node}

        def walk(current):
            for dependency in self.dependencies_of(current):
                if dependency in visited:
                    continue

                visited.add(dependency)
                reachable.add(dependency)

                walk(dependency)

        walk(node)

        return sorted(reachable)

    def reverse_reachable_from(self, node):
        reachable = set()
        visited = {node}

        def walk(current):
            for dependent in self.dependents_of(current):
                if dependent in visited:
                    continue

                visited.add(dependent)
                reachable.add(dependent)

                walk(dependent)

        walk(node)

        return sorted(reachable)

    def nodes_at_distance(self, node, distance):
        if distance < 0:
            return []

        if distance == 0:
            return [node] if node in self.nodes else []

        current_level = {node}
        visited = {node}

        for _ in range(distance):
            next_level = set()

            for current in current_level:
                for dependency in self.dependencies_of(current):
                    if dependency in visited:
                        continue

                    visited.add(dependency)
                    next_level.add(dependency)

            current_level = next_level

            if not current_level:
                break

        return sorted(current_level)

    def find_path(self, source, target):
        if source not in self.nodes:
            return []

        if target not in self.nodes:
            return []

        if source == target:
            return [source]

        queue = [[source]]
        visited = {source}

        while queue:
            path = queue.pop(0)
            current = path[-1]

            for dependency in sorted(
                self.dependencies_of(current)
            ):
                if dependency in visited:
                    continue

                next_path = path + [dependency]

                if dependency == target:
                    return next_path

                visited.add(dependency)
                queue.append(next_path)

        return []


    def reachable_count(self, node):
        return len(self.reachable_from(node))

    def reverse_reachable_count(self, node):
        return len(self.reverse_reachable_from(node))

    def reachability_stats(self, node):
        return {
            "reachable": self.reachable_count(node),
            "reverse_reachable": self.reverse_reachable_count(node),
        }
