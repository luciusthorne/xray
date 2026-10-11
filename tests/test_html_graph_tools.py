from xray.html import render_html

DATA = {
    "root": "/x/tool",
    "nodes": [
        {"id": "/x/tool", "kind": "shell", "package": None, "symbol_count": 0}
    ],
    "edges": [],
    "metadata": {"truncated": False, "xray_version": "0.0.0"},
}


def test_page_has_a_cycles_button():
    assert 'id="cycles"' in render_html(DATA)


def test_page_explains_shift_click_paths():
    assert "Shift-click" in render_html(DATA)


def test_graph_tools_load_nothing_from_the_network():
    page = render_html(DATA).replace("http://www.w3.org/2000/svg", "")

    for loader in ("src=", "href=", "@import", "url(", "fetch(", "http://", "https://"):
        assert loader not in page, loader
