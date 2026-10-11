from xray.html import render_html

DATA = {
    "root": "/x/tool",
    "nodes": [
        {"id": "/x/tool", "kind": "shell", "package": None, "symbol_count": 0}
    ],
    "edges": [],
    "metadata": {"truncated": False, "xray_version": "0.0.0"},
}


def test_panel_summarizes_reach_and_impact():
    page = render_html(DATA)

    assert "Reaches:" in page
    assert "Affected if changed:" in page


def test_panel_reports_cycle_membership():
    assert "Cycles:" in render_html(DATA)


def test_explorer_loads_nothing_from_the_network():
    page = render_html(DATA).replace("http://www.w3.org/2000/svg", "")

    for loader in ("src=", "href=", "@import", "url(", "fetch(", "http://", "https://"):
        assert loader not in page, loader
