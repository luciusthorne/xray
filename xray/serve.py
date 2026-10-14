import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from xray.graphjson import graph_data
from xray.html import render_html
from xray.minidebug import read_function_table
from xray.rizinview import function_lines
from xray.sourcelookup import file_lines, source_files, source_lines


def make_server(path, data, port=0):
    """Return an HTTP server bound to 127.0.0.1 that serves one binary.

    It serves the graph page and two read-only endpoints, /api/source
    and /api/disasm. A name must be in the binary's own function table,
    and every reply is plain text.
    """

    path = Path(path).resolve()
    known = {entry[2] for entry in read_function_table(path)}
    page = render_html(data, serve=True).encode("utf-8")
    lock = threading.Lock()
    cache = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body, kind="text/plain"):
            raw = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", f"{kind}; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            url = urlparse(self.path)

            if url.path == "/":
                return self.reply(200, page, "text/html")

            if url.path in ("/api/files", "/api/file"):
                with lock:
                    if "files" not in cache:
                        cache["files"] = source_files(path)
                files, root = cache["files"]

                if url.path == "/api/files":
                    body = (
                        {"error": root}
                        if files is None
                        else {"files": {f: len(n) for f, n in files.items()}}
                    )
                    return self.reply(200, json.dumps(body), "application/json")

                wanted = parse_qs(url.query).get("path", [])

                if files is None or len(wanted) != 1 or wanted[0] not in files:
                    return self.reply(404, "unknown file")

                return self.reply(200, "\n".join(file_lines(root, wanted[0])))

            if url.path not in ("/api/source", "/api/disasm"):
                return self.reply(404, "not found")

            names = parse_qs(url.query).get("name", [])

            if len(names) != 1:
                return self.reply(400, "missing name")

            name = names[0]

            if name not in known:
                return self.reply(404, "unknown function")

            with lock:
                if url.path == "/api/source":
                    lines = source_lines(path, name)
                else:
                    lines = function_lines(path, name)

            self.reply(200, "\n".join(lines))

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(path, open_browser=True):
    """Serve the graph page of a binary until interrupted."""

    data = graph_data(path, functions=True)
    server = make_server(path, data)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Serving {url}  (Ctrl+C to stop)")

    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped")
    finally:
        server.server_close()
