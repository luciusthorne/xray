from xray.callgraph import CallGraph, build_call_graph


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def test_add_call_creates_nodes_and_edge():
    graph = CallGraph()

    graph.add_call("a.py:f", "b.py:g")

    assert graph.nodes == {"a.py:f", "b.py:g"}
    assert graph.callees_of("a.py:f") == ["b.py:g"]
    assert graph.callers_of("b.py:g") == ["a.py:f"]


def test_duplicate_calls_make_one_edge():
    graph = CallGraph()

    graph.add_call("a.py:f", "b.py:g")
    graph.add_call("a.py:f", "b.py:g")

    assert graph.edges == [("a.py:f", "b.py:g")]


def test_callees_and_callers_are_sorted():
    graph = CallGraph()

    graph.add_call("a.py:f", "z.py:z")
    graph.add_call("a.py:f", "b.py:b")
    graph.add_call("y.py:y", "z.py:z")
    graph.add_call("c.py:c", "z.py:z")

    assert graph.callees_of("a.py:f") == ["b.py:b", "z.py:z"]
    assert graph.callers_of("z.py:z") == [
        "a.py:f",
        "c.py:c",
        "y.py:y",
    ]


def test_reachable_follows_chain():
    graph = CallGraph()

    graph.add_call("m.py:main", "m.py:calculate")
    graph.add_call("m.py:calculate", "m.py:validate")

    assert graph.reachable_from("m.py:main") == [
        "m.py:calculate",
        "m.py:validate",
    ]


def test_reachable_handles_cycles():
    graph = CallGraph()

    graph.add_call("m.py:a", "m.py:b")
    graph.add_call("m.py:b", "m.py:a")

    assert graph.reachable_from("m.py:a") == ["m.py:b"]


def test_reachable_from_unknown_node_is_empty():
    assert CallGraph().reachable_from("m.py:nothing") == []


def test_recursion_is_an_edge_but_not_reachable():
    graph = CallGraph()

    graph.add_call("m.py:f", "m.py:f")

    assert graph.callees_of("m.py:f") == ["m.py:f"]
    assert graph.reachable_from("m.py:f") == []


def test_unresolved_calls_are_kept_apart():
    graph = CallGraph()

    graph.add_unresolved("a.py:f", "calculate", "unresolved")

    assert graph.callees_of("a.py:f") == []
    assert graph.unresolved_from("a.py:f") == [
        ("calculate", "unresolved"),
    ]


def test_build_single_file(tmp_path):
    write(
        tmp_path,
        "main.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "def main():\n"
        "    helper()\n",
    )

    graph = build_call_graph(tmp_path)

    assert graph.callees_of("main.py:main") == ["main.py:helper"]
    assert graph.callers_of("main.py:helper") == ["main.py:main"]


def test_build_across_files(tmp_path):
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

    graph = build_call_graph(tmp_path)

    assert graph.callees_of("main.py:run") == ["utils.py:calculate"]
    assert graph.reachable_from("main.py:run") == [
        "utils.py:calculate",
        "utils.py:validate",
    ]


def test_build_method_call(tmp_path):
    write(
        tmp_path,
        "main.py",
        "class User:\n"
        "    def save(self):\n"
        "        self.validate()\n"
        "\n"
        "    def validate(self):\n"
        "        pass\n",
    )

    graph = build_call_graph(tmp_path)

    assert graph.callees_of("main.py:User.save") == [
        "main.py:User.validate",
    ]


def test_build_class_instantiation(tmp_path):
    write(
        tmp_path,
        "main.py",
        "class User:\n"
        "    pass\n"
        "\n"
        "def make():\n"
        "    return User()\n",
    )

    graph = build_call_graph(tmp_path)

    assert graph.callees_of("main.py:make") == ["main.py:User"]


def test_build_records_unresolved_and_external(tmp_path):
    write(tmp_path, "utils.py", "def other():\n    pass\n")
    write(
        tmp_path,
        "main.py",
        "from os import getcwd\n"
        "from utils import calculate\n"
        "\n"
        "def run():\n"
        "    calculate()\n"
        "    getcwd()\n",
    )

    graph = build_call_graph(tmp_path)

    assert graph.callees_of("main.py:run") == []
    assert graph.unresolved_from("main.py:run") == [
        ("calculate", "unresolved"),
        ("getcwd", "external"),
    ]


def test_build_package_with_relative_import(tmp_path):
    write(tmp_path, "pkg/__init__.py", "")
    write(
        tmp_path,
        "pkg/helpers.py",
        "def run_helper():\n    pass\n",
    )
    write(
        tmp_path,
        "pkg/main.py",
        "from .helpers import run_helper\n"
        "\n"
        "def go():\n"
        "    run_helper()\n",
    )

    graph = build_call_graph(tmp_path)

    assert graph.callees_of("pkg/main.py:go") == [
        "pkg/helpers.py:run_helper",
    ]


def test_build_skips_broken_files(tmp_path):
    write(tmp_path, "broken.py", "def broken(:\n")
    write(
        tmp_path,
        "main.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "def main():\n"
        "    helper()\n",
    )

    graph = build_call_graph(tmp_path)

    assert graph.callees_of("main.py:main") == ["main.py:helper"]


def test_build_ignores_pycache(tmp_path):
    write(
        tmp_path,
        "__pycache__/cached.py",
        "def helper():\n"
        "    pass\n"
        "\n"
        "def run():\n"
        "    helper()\n",
    )

    assert build_call_graph(tmp_path).nodes == set()


def test_inheritance_is_not_a_call(tmp_path):
    write(
        tmp_path,
        "main.py",
        "class Base:\n"
        "    pass\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n",
    )

    graph = build_call_graph(tmp_path)

    assert graph.edges == []
    assert graph.nodes == set()


def test_build_empty_project(tmp_path):
    graph = build_call_graph(tmp_path)

    assert graph.nodes == set()
    assert graph.edges == []
