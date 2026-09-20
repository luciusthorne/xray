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


def test_build_project_resolves_absolute_package_import(
    tmp_path,
):
    package = tmp_path / "package"
    package.mkdir()

    (package / "__init__.py").write_text("")
    (package / "database.py").write_text("")

    source = tmp_path / "main.py"
    source.write_text(
        "from package import database\n"
    )

    from xray.analyze import analyze_python

    graph = DependencyGraph()

    graph.build_project(
        tmp_path,
        analyze_python,
        tmp_path,
    )

    assert (
        "main.py",
        "package/database.py",
    ) in graph.edges


def test_build_project_resolves_imported_package_module(
    tmp_path,
):
    package = tmp_path / "package"
    package.mkdir()

    (package / "__init__.py").write_text("")
    (package / "database.py").write_text("")

    source = tmp_path / "main.py"
    source.write_text(
        "from package import database\n"
    )

    from xray.analyze import analyze_python

    graph = DependencyGraph()

    graph.build_project(
        tmp_path,
        analyze_python,
        tmp_path,
    )

    assert (
        "main.py",
        "package/database.py",
    ) in graph.edges


def test_reachable_from():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("B", "D")
    graph.add_edge("C", "E")

    assert graph.reachable_from("A") == [
        "B",
        "C",
        "D",
        "E",
    ]

    assert graph.reachable_from("C") == [
        "E",
    ]

    assert graph.reachable_from("E") == []


def test_reverse_reachable_from():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("B", "D")
    graph.add_edge("C", "E")

    assert graph.reverse_reachable_from("E") == [
        "A",
        "B",
        "C",
    ]

    assert graph.reverse_reachable_from("D") == [
        "A",
        "B",
    ]

    assert graph.reverse_reachable_from("A") == []


def test_reachability_counts():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("B", "D")
    graph.add_edge("C", "E")

    assert graph.reachable_count("A") == 4
    assert graph.reachable_count("B") == 3
    assert graph.reachable_count("C") == 1
    assert graph.reachable_count("E") == 0

    assert graph.reverse_reachable_count("E") == 3
    assert graph.reverse_reachable_count("D") == 2
    assert graph.reverse_reachable_count("A") == 0


def test_reachability_stats():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "D")

    assert graph.reachability_stats("A") == {
        "reachable": 3,
        "reverse_reachable": 0,
    }

    assert graph.reachability_stats("C") == {
        "reachable": 1,
        "reverse_reachable": 2,
    }


def test_find_path():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "D")

    assert graph.find_path("A", "D") == [
        "A",
        "B",
        "C",
        "D",
    ]


def test_find_path_returns_shortest_path():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("A", "C")
    graph.add_edge("B", "D")
    graph.add_edge("C", "D")

    assert graph.find_path("A", "D") == [
        "A",
        "B",
        "D",
    ]


def test_find_path_handles_missing_nodes():
    graph = DependencyGraph()

    graph.add_edge("A", "B")

    assert graph.find_path("A", "X") == []
    assert graph.find_path("X", "A") == []


def test_find_path_handles_same_node():
    graph = DependencyGraph()

    graph.add_node("A")

    assert graph.find_path("A", "A") == ["A"]


def test_find_path_handles_cycle():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "A")

    assert graph.find_path("A", "C") == [
        "A",
        "B",
        "C",
    ]
def test_cycle_count_with_multiple_cycles():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "A")

    graph.add_edge("C", "D")
    graph.add_edge("D", "E")
    graph.add_edge("E", "C")

    graph.add_edge("F", "G")

    assert graph.cycle_count() == 2


def test_cycle_count_ignores_normal_dependencies():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "D")

    assert graph.cycle_count() == 0


def test_cycle_count_detects_self_loop():
    graph = DependencyGraph()

    graph.add_edge("A", "A")

    assert graph.cycle_count() == 1


def test_strongly_connected_components():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "A")

    graph.add_edge("C", "D")
    graph.add_edge("D", "E")
    graph.add_edge("E", "C")

    graph.add_edge("F", "G")

    components = graph.strongly_connected_components()

    assert ["A", "B"] in components
    assert ["C", "D", "E"] in components
    assert ["F"] in components
    assert ["G"] in components


def test_strongly_connected_components_handles_empty_graph():
    graph = DependencyGraph()

    assert graph.strongly_connected_components() == []


def test_cycle_count_handles_empty_graph():
    graph = DependencyGraph()

    assert graph.cycle_count() == 0
def test_dependencies_of_unknown_node():
    graph = DependencyGraph()

    graph.add_edge("A", "B")

    assert graph.dependencies_of("X") == []


def test_dependents_of_unknown_node():
    graph = DependencyGraph()

    graph.add_edge("A", "B")

    assert graph.dependents_of("X") == []


def test_dependency_depth_handles_cycle():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "A")

    assert graph.dependency_depth("A") == 2


def test_dependency_depth_handles_missing_node():
    graph = DependencyGraph()

    graph.add_edge("A", "B")

    assert graph.dependency_depth("X") == 0


def test_reachable_from_handles_cycle():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "A")
    graph.add_edge("C", "D")

    assert graph.reachable_from("A") == [
        "B",
        "C",
        "D",
    ]


def test_reverse_reachable_from_handles_cycle():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("B", "C")
    graph.add_edge("C", "A")
    graph.add_edge("C", "D")

    assert graph.reverse_reachable_from("D") == [
        "A",
        "B",
        "C",
    ]


def test_find_path_prefers_deterministic_shortest_path():
    graph = DependencyGraph()

    graph.add_edge("A", "C")
    graph.add_edge("A", "B")
    graph.add_edge("B", "D")
    graph.add_edge("C", "D")

    assert graph.find_path("A", "D") == [
        "A",
        "B",
        "D",
    ]


def test_find_path_returns_empty_when_unreachable():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("C", "D")

    assert graph.find_path("A", "D") == []


def test_leaf_nodes_with_multiple_branches():
    graph = DependencyGraph()

    graph.add_edge("A", "B")
    graph.add_edge("A", "C")
    graph.add_edge("B", "D")
    graph.add_edge("C", "E")

    assert graph.leaf_nodes() == [
        "D",
        "E",
    ]


def test_dependency_hotspots_are_deterministic():
    graph = DependencyGraph()

    graph.add_edge("A", "C")
    graph.add_edge("B", "C")
    graph.add_edge("D", "B")
    graph.add_edge("E", "B")

    assert graph.dependency_hotspots() == [
        ("B", 2),
        ("C", 2),
    ]
