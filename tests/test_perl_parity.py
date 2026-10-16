import xray.command_analyzers as ca
from xray.calls import calls_lines
from xray.chain import chain_lines
from xray.entrypoints import command_kind
from xray.overview import overview_lines


def perl(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/perl\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def libs(tmp_path, monkeypatch):
    lib = tmp_path / "lib"
    (lib / "Foo").mkdir(parents=True)
    (lib / "Foo" / "Bar.pm").write_text("use Foo::Baz;\n", encoding="utf-8")
    (lib / "Foo" / "Baz.pm").write_text("use Foo::Bar;\n", encoding="utf-8")
    monkeypatch.setattr(ca, "perl_inc", lambda: (str(lib),))

    return lib


def test_pm_and_pl_files_are_perl(tmp_path):
    for name in ("A.pm", "b.pl"):
        path = tmp_path / name
        path.write_text("1;\n", encoding="utf-8")

        assert command_kind(path) == "perl"


def test_calls_lists_subs_and_modules(tmp_path, monkeypatch):
    lib = libs(tmp_path, monkeypatch)
    tool = perl(tmp_path / "tool", "use Foo::Bar;\nuse Gone::Away;\nsub go {\n}\n")

    lines = calls_lines(tool)

    assert lines[:2] == ["Functions:", "- go"]
    assert f"- Foo::Bar -> {(lib / 'Foo' / 'Bar.pm').resolve()} [perl]" in lines
    assert "- Gone::Away -> not found" in lines


def test_chain_follows_modules_and_ends_on_cycles(tmp_path, monkeypatch):
    lib = libs(tmp_path, monkeypatch)
    tool = perl(tmp_path / "tool", "use Foo::Bar;\n")

    lines = chain_lines(tool)

    assert lines[0] == f"{tool.resolve()} [perl]"
    assert any("Foo::Bar" in l and "[perl]" in l for l in lines)
    assert any("Foo::Baz" in l for l in lines)
    assert any("(seen)" in l for l in lines)


def test_overview_has_modules_and_chain(tmp_path, monkeypatch):
    libs(tmp_path, monkeypatch)
    tool = perl(tmp_path / "tool", "use Foo::Bar;\n")

    lines = overview_lines(tool)

    assert "Modules:" in lines
    assert "Chain:" in lines
