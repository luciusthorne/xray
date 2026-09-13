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
