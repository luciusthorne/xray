import json
import re

from xray.evidence import build_evidence_graph
from xray.evidencehtml import render, view_data
from xray.verbs import run_verb


def tool(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    helper = bin_dir / "helper"
    helper.write_text("#!/bin/sh\necho hi\n")
    helper.chmod(0o755)
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\nhelper\nmissing-cmd\n")
    path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin")
    return path, helper


def test_names_are_folded_into_the_files_they_resolve_to(tmp_path, monkeypatch):
    path, helper = tool(tmp_path, monkeypatch)
    data = view_data(build_evidence_graph(str(path), packages=False))
    edges = {(edge["source"], edge["target"]): edge for edge in data["edges"]}
    root = str(path.resolve())

    edge = edges[(root, str(helper.resolve()))]
    assert edge["via"] == "helper" and edge["kinds"] == ["runs"] and edge["basis"] == "inferred"
    assert [item["method"] for item in edge["evidence"]] == ["shell-parse", "PATH"]
    missing = next(node for node in data["nodes"] if node["label"] == "missing-cmd")
    assert missing["missing"] and missing["depth"] == 1
    assert not any(node["id"] == "command:helper" for node in data["nodes"])


def test_page_embeds_the_data_safely(tmp_path, monkeypatch):
    from xray.evidence import Evidence

    path, _ = tool(tmp_path, monkeypatch)
    graph = build_evidence_graph(str(path), packages=False)
    node = graph.add_node("command:evil</script><b>", "command", "evil</script><b>", resolved=False)
    graph.add_link(graph.root, node.id, "runs", Evidence("inferred", "test", "x"))
    page = render(graph)
    payload = re.search(r'<script id="data" type="application/json">(.*?)</script>', page, re.DOTALL).group(1)

    assert json.loads(payload)["root"] == str(path.resolve())
    assert page.count("</script>") == 2
    assert "<title>tool — XRAY evidence graph</title>" in page


def test_inspect_html_flag(tmp_path, monkeypatch, capsys):
    path, _ = tool(tmp_path, monkeypatch)

    assert run_verb(["inspect", str(path), "--html", "--no-packages"]) == 0
    assert capsys.readouterr().out.lstrip().startswith("<!doctype html>")
