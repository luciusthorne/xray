from xray.html import render_html

DATA = {"root": "/x/t", "nodes": [], "edges": [], "metadata": {}}


def test_both_themes_define_variables():
    page = render_html(DATA)

    assert ":root" in page
    assert '[data-theme="light"]' in page
    assert "--bg:" in page


def test_toggle_and_resize_handle_exist():
    page = render_html(DATA)

    assert 'id="theme"' in page
    assert 'id="resizer"' in page


def test_theme_choice_uses_guarded_storage():
    page = render_html(DATA)

    assert "localStorage" in page
    assert "try {" in page


def test_theme_loads_nothing_from_the_network():
    page = render_html(DATA).replace("http://www.w3.org/2000/svg", "")

    for banned in ("src=", "href=", "@import", "url(", "fetch(", "http://", "https://"):
        assert banned not in page, banned
