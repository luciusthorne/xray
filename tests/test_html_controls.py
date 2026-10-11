from xray.html import render_html

DATA = {
    "root": "/x/tool",
    "nodes": [
        {"id": "/x/tool", "kind": "shell", "package": None, "symbol_count": 0}
    ],
    "edges": [],
    "metadata": {"truncated": False, "xray_version": "0.0.0"},
}


def test_page_has_a_search_box():
    page = render_html(DATA)

    assert '<input id="search"' in page


def test_page_has_a_checkbox_per_kind():
    page = render_html(DATA)

    for kind in ("python", "shell", "elf", "library"):
        assert f'data-kind="{kind}"' in page


def test_controls_load_nothing_from_the_network():
    page = render_html(DATA).replace("http://www.w3.org/2000/svg", "")

    for loader in ("src=", "href=", "@import", "url(", "fetch(", "http://", "https://"):
        assert loader not in page, loader
