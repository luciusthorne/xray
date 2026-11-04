
import xray.command_analyzers as analyzers_module
import xray.perlscan as perlscan_module
from xray.analyzers import registry
from xray.command_analyzers import PerlAnalyzer
from xray.export import export_data
from xray.model import Edge
from xray.symbols import Symbol


def make(tmp_path, body):
    path = tmp_path / "tool"
    path.write_text("#!/usr/bin/perl\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def test_imports_are_resolved_or_unresolved(tmp_path, monkeypatch):
    module = tmp_path / "lib" / "Foo" / "Bar.pm"
    module.parent.mkdir(parents=True)
    module.write_text("1;\n", encoding="utf-8")
    monkeypatch.setattr(
        analyzers_module, "perl_inc", lambda: (str(tmp_path / "lib"),)
    )
    tool = make(tmp_path, "use strict;\nuse Foo::Bar;\nuse Gone::Away;\n")

    edges = PerlAnalyzer().edges(tool)
    source = str(tool.resolve())

    assert edges == [
        Edge(source, str(module.resolve()), "imports", "resolved"),
        Edge(source, None, "imports", "unresolved"),
    ]
    assert [edge.name for edge in edges] == ["Foo::Bar", "Gone::Away"]


def test_subs_become_function_symbols(tmp_path):
    tool = make(tmp_path, "sub helper {\n}\n")

    assert PerlAnalyzer().symbols(tool) == [
        Symbol("helper", "function", str(tool.resolve()), 2)
    ]


def test_registry_picks_the_perl_analyzer(tmp_path):
    assert registry.analyzer_for(make(tmp_path, "use strict;\n")).name == "perl"


def test_json_export_uses_it(tmp_path):
    data = export_data(make(tmp_path, "use Gone::Away;\n"))

    assert data["analyzer"] == "perl"
    assert data["edges"][0]["status"] == "unresolved"


def test_missing_perl_falls_back_to_default_paths(monkeypatch):
    def run(command, **kwargs):
        raise FileNotFoundError("perl")

    monkeypatch.setattr(perlscan_module.subprocess, "run", run)
    perlscan_module.perl_inc.cache_clear()

    try:
        assert perlscan_module.perl_inc() == perlscan_module.DEFAULT_INC
    finally:
        perlscan_module.perl_inc.cache_clear()
