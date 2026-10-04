from types import SimpleNamespace

import pytest

from xray.callgraph import CallGraph, build_call_graph
from xray.coupling import (
    CallCoupling,
    ModuleCoupling,
    calculate_call_coupling,
    calculate_coupling,
)
from xray.graph import DependencyGraph


def build(*edges, nodes=()):
    graph = DependencyGraph()

    for node in nodes:
        graph.add_node(node)

    for source, target in edges:
        graph.add_edge(source, target)

    return graph


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


# ----------------------------------------------------------------------
# ModuleCoupling
# ----------------------------------------------------------------------


def test_module_coupling_counts():
    module = ModuleCoupling("a.py", ("b.py", "c.py"), ("d.py",))

    assert module.fan_in == 2
    assert module.fan_out == 1
    assert module.coupling == 3


def test_instability_values():
    assert ModuleCoupling("a.py", ("b.py",), ()).instability == 0.0
    assert ModuleCoupling("a.py", (), ("b.py",)).instability == 1.0
    assert ModuleCoupling("a.py", ("b.py",), ("c.py",)).instability == 0.5
    assert ModuleCoupling("a.py").instability is None


# ----------------------------------------------------------------------
# Import coupling
# ----------------------------------------------------------------------


def test_empty_graph():
    project = calculate_coupling(DependencyGraph())

    assert project.module_count == 0
    assert project.edge_count == 0
    assert project.density == 0.0
    assert project.max_fan_in == 0
    assert project.max_fan_out == 0
    assert project.most_coupled() == []


def test_single_module_is_isolated():
    project = calculate_coupling(build(nodes=["a.py"]))

    module = project.get("a.py")

    assert module.fan_in == 0
    assert module.fan_out == 0
    assert module.coupling == 0
    assert module.instability is None


def test_simple_dependency():
    project = calculate_coupling(build(("a.py", "b.py")))

    assert project.get("a.py").fan_out == 1
    assert project.get("a.py").fan_in == 0
    assert project.get("b.py").fan_in == 1
    assert project.get("b.py").fan_out == 0


def test_incoming_and_outgoing_are_sorted_tuples():
    project = calculate_coupling(
        build(
            ("a.py", "z.py"),
            ("a.py", "c.py"),
            ("y.py", "a.py"),
            ("b.py", "a.py"),
        )
    )

    module = project.get("a.py")

    assert module.outgoing == ("c.py", "z.py")
    assert module.incoming == ("b.py", "y.py")


def test_instability_in_a_graph():
    project = calculate_coupling(
        build(("a.py", "b.py"), ("a.py", "c.py"), ("d.py", "a.py"))
    )

    assert project.get("a.py").instability == pytest.approx(2 / 3)
    assert project.get("b.py").instability == 0.0
    assert project.get("d.py").instability == 1.0


def test_coupling_is_fan_in_plus_fan_out():
    project = calculate_coupling(
        build(("a.py", "b.py"), ("b.py", "c.py"))
    )

    assert project.get("b.py").coupling == 2


def test_density_of_two_way_pair_is_one():
    project = calculate_coupling(
        build(("a.py", "b.py"), ("b.py", "a.py"))
    )

    assert project.edge_count == 2
    assert project.density == 1.0


def test_density_of_a_chain():
    project = calculate_coupling(
        build(("a.py", "b.py"), ("b.py", "c.py"))
    )

    assert project.density == pytest.approx(1 / 3)


def test_density_of_single_module_is_zero():
    assert calculate_coupling(build(nodes=["a.py"])).density == 0.0


def test_isolated_modules_are_counted():
    project = calculate_coupling(
        build(("a.py", "b.py"), nodes=["lonely.py"])
    )

    assert project.module_count == 3
    assert project.get("lonely.py").coupling == 0


def test_modules_that_only_appear_in_edges_are_included():
    graph = SimpleNamespace(nodes=set(), edges=[("a.py", "b.py")])

    project = calculate_coupling(graph)

    assert project.module_count == 2
    assert project.get("b.py").fan_in == 1


def test_repeated_edges_count_once():
    graph = SimpleNamespace(
        nodes={"a.py", "b.py"},
        edges=[("a.py", "b.py"), ("a.py", "b.py")],
    )

    project = calculate_coupling(graph)

    assert project.get("a.py").fan_out == 1
    assert project.edge_count == 1


def test_self_dependency_is_ignored():
    graph = SimpleNamespace(nodes={"a.py"}, edges=[("a.py", "a.py")])

    project = calculate_coupling(graph)

    assert project.module_count == 1
    assert project.get("a.py").fan_in == 0
    assert project.get("a.py").fan_out == 0
    assert project.edge_count == 0


def test_modules_are_sorted_by_name():
    project = calculate_coupling(
        build(("z.py", "m.py"), ("b.py", "a.py"))
    )

    assert [m.module for m in project.modules] == [
        "a.py",
        "b.py",
        "m.py",
        "z.py",
    ]


def test_get_unknown_module_is_none():
    assert calculate_coupling(build(("a.py", "b.py"))).get("x.py") is None


def test_maximum_fan_in_and_fan_out():
    project = calculate_coupling(
        build(
            ("a.py", "hub.py"),
            ("b.py", "hub.py"),
            ("c.py", "hub.py"),
            ("hub.py", "d.py"),
        )
    )

    assert project.max_fan_in == 3
    assert project.max_fan_out == 1


def test_most_coupled_orders_highest_first_then_by_name():
    project = calculate_coupling(
        build(
            ("a.py", "hub.py"),
            ("b.py", "hub.py"),
            ("c.py", "hub.py"),
            ("hub.py", "d.py"),
        )
    )

    assert [m.module for m in project.most_coupled()] == [
        "hub.py",
        "a.py",
        "b.py",
        "c.py",
        "d.py",
    ]
    assert [m.module for m in project.most_coupled(limit=2)] == [
        "hub.py",
        "a.py",
    ]


def test_cycle_gives_each_module_one_in_and_one_out():
    project = calculate_coupling(
        build(("a.py", "b.py"), ("b.py", "c.py"), ("c.py", "a.py"))
    )

    for module in project.modules:
        assert module.fan_in == 1
        assert module.fan_out == 1
        assert module.coupling == 2


# ----------------------------------------------------------------------
# Call coupling
# ----------------------------------------------------------------------


def test_cross_module_call():
    graph = CallGraph()
    graph.add_call("a.py:f", "b.py:g")

    assert calculate_call_coupling(graph) == (
        CallCoupling("a.py", 1, 0),
        CallCoupling("b.py", 0, 1),
    )


def test_calls_inside_one_module_are_ignored():
    graph = CallGraph()
    graph.add_call("a.py:f", "a.py:g")

    assert calculate_call_coupling(graph) == (
        CallCoupling("a.py", 0, 0),
    )


def test_calls_from_several_modules_into_one():
    graph = CallGraph()
    graph.add_call("a.py:f", "b.py:g")
    graph.add_call("c.py:h", "b.py:g")

    assert calculate_call_coupling(graph) == (
        CallCoupling("a.py", 1, 0),
        CallCoupling("b.py", 0, 2),
        CallCoupling("c.py", 1, 0),
    )


def test_each_distinct_call_counts():
    graph = CallGraph()
    graph.add_call("a.py:f", "b.py:g")
    graph.add_call("a.py:f", "b.py:h")

    assert calculate_call_coupling(graph) == (
        CallCoupling("a.py", 2, 0),
        CallCoupling("b.py", 0, 2),
    )


def test_qualified_method_names_and_package_paths():
    graph = CallGraph()
    graph.add_call("pkg/a.py:User.save", "pkg/b.py:Repo.store")

    assert calculate_call_coupling(graph) == (
        CallCoupling("pkg/a.py", 1, 0),
        CallCoupling("pkg/b.py", 0, 1),
    )


def test_module_with_only_unresolved_calls_is_listed():
    graph = CallGraph()
    graph.add_unresolved("a.py:f", "missing", "unresolved")

    assert calculate_call_coupling(graph) == (
        CallCoupling("a.py", 0, 0),
    )


def test_empty_call_graph():
    assert calculate_call_coupling(CallGraph()) == ()


def test_call_coupling_from_a_real_project(tmp_path):
    write(
        tmp_path,
        "utils.py",
        "def validate():\n"
        "    pass\n"
        "\n"
        "def calculate():\n"
        "    validate()\n",
    )
    write(
        tmp_path,
        "main.py",
        "from utils import calculate\n"
        "\n"
        "def run():\n"
        "    calculate()\n",
    )

    result = calculate_call_coupling(build_call_graph(tmp_path))

    assert result == (
        CallCoupling("main.py", 1, 0),
        CallCoupling("utils.py", 0, 1),
    )
