from xray.html import render_html

DATA = {
    "root": "/x/tool",
    "nodes": [
        {"id": "/x/tool", "kind": "shell", "package": None, "symbol_count": 0}
    ],
    "edges": [],
    "metadata": {"truncated": False, "xray_version": "0.0.0"},
}


def test_page_has_an_impact_button():
    assert 'id="impact"' in render_html(DATA)


def test_impact_tool_loads_nothing_from_the_network():
    page = render_html(DATA).replace("http://www.w3.org/2000/svg", "")

    for loader in ("src=", "href=", "@import", "url(", "fetch(", "http://", "https://"):
        assert loader not in page, loader


def test_impact_styles_exist():
    page = render_html(DATA)

    assert "circle.imp1" in page
    assert "circle.imp2" in page
