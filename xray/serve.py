import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from xray.entrypoints import command_kind
from xray.graphjson import graph_data
from xray.html import render_html
from xray.locate import locate
from xray.minidebug import debuginfod_function_table, read_function_table
from xray.rizinview import function_lines
from xray.sourcelookup import file_lines, source_files, source_lines

SERVED_BUILTIN = ("elf", "shell", "perl", "ruby", "javascript", "lua", "typescript", "c", "python")
TEXT_BUILTIN = ("shell", "perl", "ruby", "javascript", "lua", "typescript", "c", "python")


def _local_host(value):
    """Accept only loopback names in HTTP Host headers."""

    if not value:
        return False

    host = value.strip().lower()

    for name in ("127.0.0.1", "localhost"):
        if host == name:
            return True

        prefix, separator, port = host.rpartition(":")
        if separator and prefix == name and port.isdigit():
            return True

    return False


class _Kinds(tuple):
    """Built-in kinds plus the kinds plugins add (looked up when tested)."""

    def __contains__(self, kind):
        from xray.analyzers import plugin_kinds

        return tuple.__contains__(self, kind) or kind in plugin_kinds()


SERVED = _Kinds(SERVED_BUILTIN)
TEXT = _Kinds(TEXT_BUILTIN)


def _unavailable(lines):
    from xray.codeview import _source_unavailable

    return _source_unavailable(lines)


def make_server(path, data, port=0):
    """Return an HTTP server bound to 127.0.0.1 for a command and the ones it leads to.

    The starting command is served at "/". "/?cmd=<name or path>" serves
    another command (ELF, shell, Perl, Ruby, JavaScript, Lua, TypeScript, C or Python files only). Read-only
    endpoints: /api/source, /api/disasm, /api/files, /api/file and
    /api/text. A function name must be in that binary's own function
    table, and a file path must be a node of a page already served.
    Every reply is plain text or JSON.
    """

    root = str(Path(path).resolve())
    lock = threading.Lock()
    pages = {root: render_html(data, serve=True).encode("utf-8")}
    allowed = {root} | {n["id"] for n in data.get("nodes", [])}
    cache = {}

    def resolve(cmd):
        if cmd in pages:
            return cmd

        found = locate(cmd)

        if found is None or command_kind(found) not in SERVED:
            return None

        return str(found)

    def page_for(target):
        with lock:
            if target not in pages:
                built = graph_data(Path(target), functions=True)
                pages[target] = render_html(built, serve=True).encode("utf-8")
                allowed.update(n["id"] for n in built.get("nodes", []))
                allowed.add(target)

            return pages[target]

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
            if not _local_host(self.headers.get("Host")):
                return self.reply(403, "host not allowed")

            url = urlparse(self.path)
            qs = parse_qs(url.query)

            def arg(key):
                value = qs.get(key, [])

                return value[0] if len(value) == 1 else None

            if url.path == "/":
                cmd = arg("cmd")

                if cmd is None:
                    return self.reply(200, pages[root], "text/html")

                target = resolve(cmd)

                if target is None:
                    return self.reply(404, "unknown command")

                return self.reply(200, page_for(target), "text/html")

            if url.path == "/api/text":
                wanted = arg("path")

                if wanted is None:
                    return self.reply(400, "missing path")

                if wanted not in allowed or command_kind(Path(wanted)) not in TEXT:
                    return self.reply(404, "not a served script")

                lines = Path(wanted).read_text(encoding="utf-8", errors="replace").splitlines()
                shown = [f"{n:5d}  {line}" for n, line in enumerate(lines[:400], 1)]

                if len(lines) > 400:
                    shown.append(f"... and {len(lines) - 400} more lines")

                return self.reply(200, "\n".join(shown))

            if url.path not in ("/api/source", "/api/disasm", "/api/files", "/api/file"):
                return self.reply(404, "not found")

            cmd = arg("cmd") or root

            if cmd not in allowed or command_kind(Path(cmd)) != "elf":
                return self.reply(404, "not a served binary")

            binary = Path(cmd)

            def mapped():
                from xray import codemap

                with lock:
                    key = ("map", cmd)
                    if key not in cache:
                        try:
                            cache[key] = codemap.code_map(binary)
                        except (OSError, ValueError):
                            cache[key] = None
                    return cache[key]

            if url.path in ("/api/files", "/api/file"):
                with lock:
                    if cmd not in cache:
                        cache[cmd] = source_files(binary)

                files, source_root = cache[cmd]

                if files is None:
                    from xray import codemap

                    cmap = mapped()
                    if cmap is not None and cmap.files:
                        if url.path == "/api/files":
                            return self.reply(200, json.dumps({"files": {f: len(fs) for f, fs in sorted(cmap.files.items())}}),
                                              "application/json")
                        wanted = arg("path")
                        if wanted not in cmap.files:
                            return self.reply(404, "unknown file")
                        with lock:
                            view = codemap.file_view(cmap, wanted, binary.name, numbered=False)
                        return self.reply(200, "\n".join(view or ["unknown file"]))

                if url.path == "/api/files":
                    body = (
                        {"error": source_root}
                        if files is None
                        else {"files": {f: len(n) for f, n in files.items()}}
                    )

                    return self.reply(200, json.dumps(body), "application/json")

                wanted = arg("path")

                if files is None or wanted not in files:
                    return self.reply(404, "unknown file")

                return self.reply(200, "\n".join(file_lines(source_root, wanted)))

            name = arg("name")

            if name is None:
                return self.reply(400, "missing name")

            known = {e[2] for e in read_function_table(binary) or debuginfod_function_table(binary)}
            cmap = None
            if name not in known:
                cmap = mapped()
                if cmap is None or name not in {f.symbol for f in cmap.functions}:
                    return self.reply(404, "unknown function")

            with lock:
                if url.path == "/api/source":
                    lines = source_lines(binary, name) if name in known else []
                else:
                    lines = function_lines(binary, name)

            if url.path == "/api/source" and _unavailable(lines):
                from xray import codemap

                cmap = cmap or mapped()
                view = codemap.function_view(cmap, name, binary.name, numbered=False) if cmap is not None else None
                if view:
                    lines = view

            self.reply(200, "\n".join(lines))

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(path, open_browser=True):
    """Serve the graph page of a command until interrupted."""

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
