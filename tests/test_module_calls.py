from xray.relationships import find_relationships


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def calls(main, root):
    return [
        (r.name, r.status, r.target)
        for r in find_relationships(main, root)
        if r.kind == "calls"
    ]


def test_module_attribute_call_resolves(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "import utils\n\n\ndef main():\n    utils.calculate()\n",
    )

    assert calls(main, tmp_path) == [
        ("utils.calculate", "resolved", "utils.py:calculate")
    ]


def test_aliased_module_call_resolves(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "import utils as u\n\n\ndef main():\n    u.calculate()\n",
    )

    assert calls(main, tmp_path) == [
        ("u.calculate", "resolved", "utils.py:calculate")
    ]


def test_submodule_call_resolves(tmp_path):
    write(tmp_path / "pkg" / "__init__.py")
    write(tmp_path / "pkg" / "sub.py", "def run():\n    pass\n")
    main = write(
        tmp_path / "main.py",
        "import pkg.sub\n\n\ndef main():\n    pkg.sub.run()\n",
    )

    assert calls(main, tmp_path) == [
        ("pkg.sub.run", "resolved", "pkg/sub.py:run")
    ]


def test_missing_function_in_local_module_is_unresolved(tmp_path):
    write(tmp_path / "utils.py", "def calculate():\n    return 1\n")
    main = write(
        tmp_path / "main.py",
        "import utils\n\n\ndef main():\n    utils.nothing()\n",
    )

    assert calls(main, tmp_path) == [
        ("utils.nothing", "unresolved", None)
    ]


def test_external_module_calls_are_not_recorded(tmp_path):
    main = write(
        tmp_path / "main.py",
        "import os\n\n\ndef main():\n    os.getcwd()\n",
    )

    assert calls(main, tmp_path) == []
