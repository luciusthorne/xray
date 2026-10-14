import threading
import urllib.error
import urllib.request

import xray.serve as sv
from xray.html import render_html


def sh(path, body="echo hi\n"):
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def start(monkeypatch, tmp_path):
    root = sh(tmp_path / "tool", "other\n")
    other = sh(tmp_path / "other")
    graphs = {
        str(other): {"root": str(other), "nodes": [{"id": str(other), "kind": "shell"}], "edges": [], "metadata": {}},
    }
    monkeypatch.setattr(sv, "graph_data", lambda p, functions=False: graphs[str(p)])
    monkeypatch.setattr(sv, "locate", lambda name: other if name == "other" else None)
    monkeypatch.setattr(sv, "read_function_table", lambda p: ())
    data = {"root": str(root), "nodes": [{"id": str(root), "kind": "shell"}], "edges": [], "metadata": {}}
    server = sv.make_server(root, data, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    return server, root, other


def get(server, path):
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"

    try:
        with urllib.request.urlopen(url) as reply:
            return reply.status, reply.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_text_endpoint_serves_graph_scripts_only(monkeypatch, tmp_path):
    server, root, _ = start(monkeypatch, tmp_path)

    try:
        status, body = get(server, f"/api/text?path={root}")
        assert status == 200 and "    1  #!/bin/sh" in body
        assert get(server, "/api/text?path=/etc/passwd")[0] == 404
        assert get(server, "/api/text")[0] == 400
    finally:
        server.shutdown()


def test_cmd_page_opens_another_command_and_allows_its_files(monkeypatch, tmp_path):
    server, root, other = start(monkeypatch, tmp_path)

    try:
        assert get(server, f"/api/text?path={other}")[0] == 404
        status, body = get(server, "/?cmd=other")
        assert status == 200 and "Open this command" in body
        assert get(server, f"/api/text?path={other}")[0] == 200
    finally:
        server.shutdown()


def test_cmd_refuses_unknown_and_non_command_files(monkeypatch, tmp_path):
    server, *_ = start(monkeypatch, tmp_path)

    try:
        assert get(server, "/?cmd=nosuchthing")[0] == 404
        assert get(server, "/?cmd=/etc/passwd")[0] == 404
    finally:
        server.shutdown()


def test_serving_page_has_navigation_and_static_page_does_not():
    data = {"root": "/x/t", "nodes": [], "edges": [], "metadata": {}}

    assert "Open this command" in render_html(data, serve=True)
    assert 'id="nav-back"' in render_html(data, serve=True)
    assert "Open this command" not in render_html(data)
