from dataclasses import dataclass


@dataclass(frozen=True)
class ModuleCoupling:
    """Coupling of one module (file) in the dependency graph.

    incoming lists the modules that depend on this one, outgoing the
    modules this one depends on. Both are sorted and hold each module
    once.

    fan_in and fan_out count them, and coupling is their sum.
    instability is fan_out / coupling: 0.0 means the module depends
    on nothing, 1.0 means nothing depends on it, and None means the
    module is isolated.
    """

    module: str
    incoming: tuple = ()
    outgoing: tuple = ()

    @property
    def fan_in(self):
        return len(self.incoming)

    @property
    def fan_out(self):
        return len(self.outgoing)

    @property
    def coupling(self):
        return self.fan_in + self.fan_out

    @property
    def instability(self):
        if self.coupling == 0:
            return None

        return self.fan_out / self.coupling


@dataclass(frozen=True)
class ProjectCoupling:
    """Coupling of every module in a dependency graph.

    density is the number of dependency edges divided by the number
    of possible edges, n * (n - 1) for n modules, and 0.0 when there
    are fewer than two modules.
    """

    modules: tuple = ()

    @property
    def module_count(self):
        return len(self.modules)

    @property
    def edge_count(self):
        return sum(module.fan_out for module in self.modules)

    @property
    def density(self):
        count = self.module_count

        if count < 2:
            return 0.0

        return self.edge_count / (count * (count - 1))

    @property
    def max_fan_in(self):
        return max(
            (module.fan_in for module in self.modules),
            default=0,
        )

    @property
    def max_fan_out(self):
        return max(
            (module.fan_out for module in self.modules),
            default=0,
        )

    def get(self, name):
        """Return the ModuleCoupling for name, or None."""

        for module in self.modules:
            if module.module == name:
                return module

        return None

    def most_coupled(self, limit=10):
        """Return the most coupled modules, highest first."""

        ranked = sorted(
            self.modules,
            key=lambda module: (-module.coupling, module.module),
        )

        return ranked[:limit]


def calculate_coupling(graph):
    """Return ProjectCoupling for a dependency graph.

    Works with any object that has nodes and edges, like
    DependencyGraph: nodes is a collection of module names and edges
    a list of (source, target) pairs meaning source depends on target.

    A module that depends on itself is ignored for the counts, and a
    repeated edge counts once. Modules that only appear in an edge are
    included.
    """

    names = set(graph.nodes)

    for source, target in graph.edges:
        names.add(source)
        names.add(target)

    outgoing = {name: set() for name in names}
    incoming = {name: set() for name in names}

    for source, target in graph.edges:
        if source != target:
            outgoing[source].add(target)
            incoming[target].add(source)

    return ProjectCoupling(
        tuple(
            ModuleCoupling(
                name,
                tuple(sorted(incoming[name])),
                tuple(sorted(outgoing[name])),
            )
            for name in sorted(names)
        )
    )


@dataclass(frozen=True)
class CallCoupling:
    """Calls that cross the boundary of one module (file).

    calls_out counts the distinct calls from functions in this module
    to functions or classes in other modules. calls_in counts the
    distinct calls from other modules into this one.
    """

    module: str
    calls_out: int = 0
    calls_in: int = 0


def _module_of(node):
    return node.rsplit(":", 1)[0]


def calculate_call_coupling(call_graph):
    """Return CallCoupling for every module in a call graph.

    This is the symbol-level view: it counts actual calls between
    modules, where calculate_coupling counts imports. Calls inside
    one module are ignored. Only calls that resolved to a definition
    are counted, as in CallGraph. Result is sorted by module name.
    """

    out = {}
    into = {}

    for node in call_graph.nodes:
        module = _module_of(node)
        out.setdefault(module, 0)
        into.setdefault(module, 0)

    for caller, callee in call_graph.edges:
        source = _module_of(caller)
        target = _module_of(callee)

        if source != target:
            out[source] += 1
            into[target] += 1

    return tuple(
        CallCoupling(module, out[module], into[module])
        for module in sorted(out)
    )
