import xray.report as rp


def script(tmp_path, body="ls\n"):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def patch(monkeypatch):
    monkeypatch.setattr(rp, "package_of", lambda p: "pkg-1-1.noarch")
    monkeypatch.setattr(rp, "overview_lines", lambda p: ["Commands:", "- ls"])
    monkeypatch.setattr(rp, "cached_source_files", lambda p: None)


def test_text_report_has_sections(tmp_path, monkeypatch):
    patch(monkeypatch)

    lines = rp.report_lines(script(tmp_path))

    assert "Identity" in lines
    assert "Package: pkg-1-1.noarch" in lines
    assert "Kind: shell" in lines
    assert "Overview" in lines
    assert "- ls" in lines
    assert any("--code" in l for l in lines)


def test_markdown_report_uses_headings_and_fences(tmp_path, monkeypatch):
    patch(monkeypatch)

    lines = rp.report_lines(script(tmp_path), markdown=True)

    assert "## Identity" in lines
    assert "```" in lines
    assert "- Package: pkg-1-1.noarch" in lines


def test_cached_source_files_are_listed(tmp_path, monkeypatch):
    patch(monkeypatch)
    monkeypatch.setattr(rp, "cached_source_files", lambda p: {"src/a.c": ["f", "g"]})

    lines = rp.report_lines(script(tmp_path))

    assert "src/a.c (2 function(s))" in lines
