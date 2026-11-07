"""The graph page's layout cools to a stop and fits below the floating controls."""

from xray.html import render_html

DATA = {"root": "/usr/bin/tool", "nodes": [{"id": "/usr/bin/tool", "kind": "elf"}], "edges": []}


def test_layout_stops_and_fits_below_the_controls():
    page = render_html(DATA)

    assert 'id="fit"' in page
    assert "if (alpha < 0.004) alpha = 0;" in page  # settles instead of drifting forever
    assert "requestAnimationFrame(loop)" in page and "running = false" in page  # loop ends when settled
    assert "function freeArea()" in page and 'getElementById("controls")' in page
    assert "Math.max(alpha * 0.992, 0.03)" not in page
