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
