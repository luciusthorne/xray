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

    def resolve_local_module(self, module, project_root):
        module = module.lstrip(".")
        parts = module.split(".")

        module_path = Path(project_root).joinpath(*parts)

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
                analysis = analyze_function(path)
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

        def visit(node, path):
            if node in path:
                cycle_start = path.index(node)

                cycle = (
                    path[cycle_start:]
                    + [node]
                )

                key = canonical_cycle(cycle)

                if key not in seen:
                    seen.add(key)
                    cycles.append(cycle)

                return

            new_path = path + [node]

            for dependency in self.dependencies_of(node):
                visit(
                    dependency,
                    new_path,
                )

        for node in sorted(self.nodes):
            visit(node, [])

        return cycles

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
