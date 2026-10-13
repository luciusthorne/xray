import threading
import urllib.error
import urllib.request

import xray.serve as serve_module
from xray.html import render_html

DATA = {
    "root": "/x/t",
    "nodes": [],
    "edges": [],
    "metadata": {"truncated": False},
}


def start(monkeypatch, tmp_path):
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(
        serve_module, "source_lines", lambda p, n, say=None: [f"SRC {n}"]
    )
    monkeypatch.setattr(
        serve_module, "function_lines", lambda p, n: [f"ASM {n}"]
    )
    monkeypatch.setattr(
        serve_module, "read_function_table", lambda p: ((0x10, 4, "known_fn"),)
    )
    server = serve_module.make_server(binary, {"root": str(binary)}, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    return server


def get(server, path):
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"

    try:
        with urllib.request.urlopen(url) as reply:
            return reply.status, reply.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_server_binds_to_localhost_only(monkeypatch, tmp_path):
    server = start(monkeypatch, tmp_path)

    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.shutdown()


def test_source_and_disasm_endpoints(monkeypatch, tmp_path):
    server = start(monkeypatch, tmp_path)

    try:
        assert get(server, "/api/source?name=known_fn") == (200, "SRC known_fn")
        assert get(server, "/api/disasm?name=known_fn") == (200, "ASM known_fn")
    finally:
        server.shutdown()


def test_unknown_names_and_paths_are_refused(monkeypatch, tmp_path):
    server = start(monkeypatch, tmp_path)

    try:
        assert get(server, "/api/source?name=evil;rm")[0] == 404
        assert get(server, "/api/source")[0] == 400
        assert get(server, "/etc/passwd")[0] == 404
    finally:
        server.shutdown()


def test_index_serves_the_page_with_buttons(monkeypatch, tmp_path):
    server = start(monkeypatch, tmp_path)

    try:
        status, body = get(server, "/")
    finally:
        server.shutdown()

    assert status == 200
    assert "Show source" in body


def test_static_page_has_no_fetch_buttons():
    assert "Show source" not in render_html(DATA)
    assert "fetch(" not in render_html(DATA)
