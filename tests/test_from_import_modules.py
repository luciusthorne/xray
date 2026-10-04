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


def test_from_package_import_module_call_resolves(tmp_path):
    write(tmp_path / "pkg" / "__init__.py")
    write(tmp_path / "pkg" / "sub.py", "def run():\n    pass\n")
    main = write(
        tmp_path / "main.py",
        "from pkg import sub\n\n\ndef main():\n    sub.run()\n",
    )

    assert calls(main, tmp_path) == [
        ("sub.run", "resolved", "pkg/sub.py:run")
    ]


def test_from_package_import_module_with_alias(tmp_path):
    write(tmp_path / "pkg" / "__init__.py")
    write(tmp_path / "pkg" / "sub.py", "def run():\n    pass\n")
    main = write(
        tmp_path / "main.py",
        "from pkg import sub as s\n\n\ndef main():\n    s.run()\n",
    )

    assert calls(main, tmp_path) == [
        ("s.run", "resolved", "pkg/sub.py:run")
    ]


def test_relative_from_import_module_call_resolves(tmp_path):
    write(tmp_path / "pkg" / "__init__.py")
    write(tmp_path / "pkg" / "sub.py", "def run():\n    pass\n")
    main = write(
        tmp_path / "pkg" / "main.py",
        "from . import sub\n\n\ndef main():\n    sub.run()\n",
    )

    assert calls(main, tmp_path) == [
        ("sub.run", "resolved", "pkg/sub.py:run")
    ]


def test_imported_function_attribute_is_not_a_module_call(tmp_path):
    write(tmp_path / "pkg" / "__init__.py", "def helper():\n    pass\n")
    main = write(
        tmp_path / "main.py",
        "from pkg import helper\n\n\ndef main():\n    helper.attr()\n",
    )

    assert calls(main, tmp_path) == []
