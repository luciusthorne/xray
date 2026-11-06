import json

from xray.evidence import Evidence, build_evidence_graph
from xray.sbom import cyclonedx, spdx
from xray.verbs import run_verb


def graph_of(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    helper = bin_dir / "helper"
    helper.write_text("#!/bin/sh\necho hi\n")
    helper.chmod(0o755)
    tool = tmp_path / "tool"
    tool.write_text("#!/bin/sh\nhelper\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin")
    graph = build_evidence_graph(str(tool), packages=False)
    package = graph.add_node("package:demo", "package", "demo 1.0-1", manager="pacman")
    graph.add_link(str(helper.resolve()), package.id, "owned_by", Evidence("declared", "pacman", "pacman -Qo"))
    return graph, tool.resolve(), helper.resolve()


def test_cyclonedx_lists_files_packages_and_evidenced_dependencies(tmp_path, monkeypatch):
    graph, tool, helper = graph_of(tmp_path, monkeypatch)
    bom = cyclonedx(graph)

    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.6")
    assert bom["metadata"]["component"]["bom-ref"] == str(tool)
    refs = {component["bom-ref"]: component for component in bom["components"]}
    assert refs["package:demo"]["purl"] == "pkg:alpm/arch/demo@1.0-1"
    assert refs[str(helper)]["hashes"][0]["alg"] == "SHA-256"
    depends = {entry["ref"]: entry["dependsOn"] for entry in bom["dependencies"]}
    assert str(helper) in depends[str(tool)]  # the interpreter is listed too
    assert "package:demo" in depends[str(helper)]
    links = [item for item in bom["metadata"]["properties"] if item["name"].startswith("xray:link:")]
    assert any(link["value"] == "runs [inferred] via helper" for link in links)


def test_spdx_files_are_relative_with_sha1_and_ownership_is_not_contains(tmp_path, monkeypatch):
    graph, _tool, _helper = graph_of(tmp_path, monkeypatch)
    doc = spdx(graph)

    assert doc["spdxVersion"] == "SPDX-2.3"
    assert all(item["fileName"].startswith("./") for item in doc["files"])
    assert all({checksum["algorithm"] for checksum in item["checksums"]} == {"SHA1", "SHA256"} for item in doc["files"])
    kinds = {relationship["relationshipType"] for relationship in doc["relationships"]}
    assert "CONTAINS" not in kinds and {"DESCRIBES", "DEPENDS_ON", "OTHER"} <= kinds


def test_inspect_sbom_flag(tmp_path, monkeypatch, capsys):
    _graph, tool, _helper = graph_of(tmp_path, monkeypatch)

    assert run_verb(["inspect", str(tool), "--sbom", "cyclonedx", "--no-packages"]) == 0
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"
