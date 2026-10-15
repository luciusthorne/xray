from xray.html import render_html

DATA = {"root": "/x/t", "nodes": [], "edges": [], "metadata": {}}


def test_pages_have_the_tab_code():
    for page in (render_html(DATA), render_html(DATA, serve=True)):
        assert "function tabify" in page
        assert "tabbar" in page


def test_tabs_name_the_three_groups():
    page = render_html(DATA)

    for name in ("Overview", "Edges", "Code"):
        assert f'"{name}"' in page


def test_tabs_load_nothing_from_the_network():
    page = render_html(DATA).replace("http://www.w3.org/2000/svg", "")

    for banned in ("src=", "href=", "@import", "url(", "fetch(", "http://", "https://"):
        assert banned not in page, banned
