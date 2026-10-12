import xray.graphjson as graphjson_module
from xray.disasm import DisasmResult
from xray.graphjson import graph_data


def elf(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"\x7fELF" + bytes(60))

    return path


RESULT = DisasmResult(
    {"main": ("helper", "getenv@plt"), "helper": ("getenv@plt",)}
)


def patch(monkeypatch, result=RESULT):
    monkeypatch.setattr(graphjson_module, "package_of", lambda p: None)
    monkeypatch.setattr(graphjson_module, "disasm_result", lambda p: result)
    monkeypatch.setattr(
        graphjson_module.registry, "analyzer_for", lambda p: None
    )


def test_functions_become_nodes_and_edges(tmp_path, monkeypatch):
    patch(monkeypatch)
    binary = elf(tmp_path)

    data = graph_data(binary, functions=True)
    kinds = {n["id"].split(":")[-1]: n["kind"] for n in data["nodes"]}
    root = str(binary.resolve())

    assert kinds["main"] == "function"
    assert kinds["helper"] == "function"
    assert kinds["getenv"] == "import"
    assert {
        "source": f"{root}:main",
        "target": f"{root}:helper",
        "kind": "calls",
        "status": "resolved",
        "name": "helper",
    } in data["edges"]
    assert {
        "source": f"{root}:helper",
        "target": "import:getenv",
        "kind": "calls",
        "status": "resolved",
        "name": "getenv",
    } in data["edges"]


def test_functions_are_off_by_default(tmp_path, monkeypatch):
    patch(monkeypatch)

    data = graph_data(elf(tmp_path))

    assert not any(n["kind"] == "function" for n in data["nodes"])


def test_function_cap_is_reported(tmp_path, monkeypatch):
    patch(monkeypatch)

    data = graph_data(elf(tmp_path), functions=True, max_functions=1)

    assert len([n for n in data["nodes"] if n["kind"] == "function"]) == 1
    assert data["metadata"]["truncated"] is True


def test_non_elf_root_gets_no_functions(tmp_path, monkeypatch):
    patch(monkeypatch)
    tool = tmp_path / "tool"
    tool.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    tool.chmod(0o755)

    data = graph_data(tool, functions=True)

    assert not any(n["kind"] == "function" for n in data["nodes"])


def test_page_has_function_and_import_filters():
    from xray.html import render_html

    page = render_html(
        {
            "root": "/x/t",
            "nodes": [],
            "edges": [],
            "metadata": {"truncated": False},
        }
    )

    assert 'data-kind="function"' in page
    assert 'data-kind="import"' in page
