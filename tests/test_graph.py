from xray.graph import DependencyGraph


def test_basic_counts():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")

    assert graph.node_count() == 3
    assert graph.edge_count() == 2


def test_leaf_nodes():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")

    assert graph.leaf_nodes() == ["c.py"]


def test_dependency_depth():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")

    assert graph.dependency_depth("a.py") == 2


def test_cycle_detection():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")
    graph.add_edge("c.py", "a.py")

    assert graph.cycle_count() == 1


def test_dependency_hotspots():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("c.py", "b.py")
    graph.add_edge("d.py", "a.py")

    assert graph.dependency_hotspots() == [
        ("b.py", 2),
        ("a.py", 1),
    ]


def test_dependency_tree_handles_cycle():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")
    graph.add_edge("c.py", "a.py")

    assert graph.dependency_tree("a.py") == [
        "a.py",
        "└── b.py",
        "    └── c.py",
        "        └── a.py",
    ]


def test_impact_of_cycle():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")
    graph.add_edge("c.py", "a.py")

    assert graph.impact_of("a.py") == {
        "direct": ["c.py"],
        "indirect": ["b.py"],
    }


def test_impact_chains_handles_cycle():
    graph = DependencyGraph()

    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")
    graph.add_edge("c.py", "a.py")

    assert graph.impact_chains("a.py") == [
        ["a.py", "c.py", "b.py", "a.py"]
    ]
