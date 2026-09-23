from xray.analyze import analyze_python


def test_analyze_import(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("import os\n")

    result = analyze_python(source)

    assert result["imports"] == [
        {
            "module": "os",
            "name": None,
            "alias": None,
            "relative": False,
        }
    ]


def test_analyze_relative_import_without_module(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("from . import utils\n")

    result = analyze_python(source)

    assert result["imports"] == [
        {
            "module": ".",
            "name": "utils",
            "alias": None,
            "relative": True,
        }
    ]


def test_discover_local_package_modules(tmp_path):
    package = tmp_path / "package"
    package.mkdir()

    (tmp_path / "utils.py").write_text("")
    (package / "__init__.py").write_text("")
    (package / "database.py").write_text("")

    from xray.dependencies import discover_local_modules

    modules = discover_local_modules(tmp_path)

    assert "utils" in modules
    assert "package.database" in modules


def test_discover_local_package_itself(tmp_path):
    package = tmp_path / "package"
    package.mkdir()

    (package / "__init__.py").write_text("")
    (package / "database.py").write_text("")

    from xray.dependencies import discover_local_modules

    modules = discover_local_modules(tmp_path)

    assert "package" in modules
    assert "package.database" in modules


def test_discover_nested_local_modules(tmp_path):
    package = tmp_path / "package"
    nested = package / "sub"
    nested.mkdir(parents=True)

    (package / "__init__.py").write_text("")
    (nested / "__init__.py").write_text("")
    (nested / "database.py").write_text("")

    from xray.dependencies import discover_local_modules

    modules = discover_local_modules(tmp_path)

    assert "package" in modules
    assert "package.sub" in modules
    assert "package.sub.database" in modules


def test_analyze_local_absolute_import(tmp_path):
    package = tmp_path / "package"
    package.mkdir()

    (package / "__init__.py").write_text("")
    (package / "database.py").write_text("")
    source = tmp_path / "main.py"
    source.write_text("from package import database\n")

    result = analyze_python(source)

    assert result["dependencies"] == [
        {
            "module": "package",
            "name": "database",
            "type": "local",
            "relative": False,
        }
    ]


def test_analyze_local_absolute_import_from_project_root(tmp_path):
    package = tmp_path / "package"
    package.mkdir()

    (package / "__init__.py").write_text("")
    (package / "database.py").write_text("")

    source = tmp_path / "main.py"
    source.write_text("from package import database\n")

    result = analyze_python(source)

    assert result["dependencies"][0]["type"] == "local"

def test_analyze_invalid_python_raises_analysis_error(tmp_path):
    from xray.analyze import analyze_python
    from xray.errors import AnalysisError

    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n", encoding="utf-8")

    try:
        analyze_python(source)
    except AnalysisError as error:
        assert str(error) == f"Invalid Python syntax: {source}"
    else:
        raise AssertionError("Expected AnalysisError")


def test_analyze_missing_file_raises_file_error(tmp_path):
    from xray.errors import FileError

    source = tmp_path / "missing.py"

    try:
        analyze_python(source)
    except FileError as error:
        assert str(error) == f"Unable to read file: {source}"
    else:
        raise AssertionError("Expected FileError")


def test_analyze_invalid_encoding_raises_file_error(tmp_path):
    from xray.errors import FileError

    source = tmp_path / "invalid.py"
    source.write_bytes(b"print('hello')\n\xff")

    try:
        analyze_python(source)
    except FileError as error:
        assert str(error) == f"Unable to decode file: {source}"
    else:
        raise AssertionError("Expected FileError")
