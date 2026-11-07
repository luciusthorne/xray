"""The code map in the graph page, --serve and --report, on a real compiled program."""

import json
import shutil
import subprocess
import threading
import urllib.request
from pathlib import Path

import pytest

from xray import codemap
from xray.graphjson import graph_data

pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("cc", "addr2line", "c++filt", "readelf", "objdump")),
    reason="needs cc and binutils",
)

PROGRAM = r'''#include <stdio.h>

__attribute__((noinline)) static int helper(int x)
{
    return x + 1;
}

int main(void)
{
    printf("%d\n", helper(1));
    return 0;
}
'''


@pytest.fixture
def tool(tmp_path):
    source = tmp_path / "tool.c"
    source.write_text(PROGRAM)
    binary = tmp_path / "tool"
    subprocess.run(["cc", "-g", "-O1", "-o", str(binary), str(source)], check=True)
    codemap._CACHE.clear()
    return binary


def test_function_nodes_carry_readable_names_files_and_lines(tool):
    data = graph_data(Path(tool), functions=True)
    main = next(node for node in data["nodes"] if node["id"].endswith(":main"))
    assert main["label"] == "main"
    assert main["metadata"]["file"].endswith("tool.c") and main["metadata"]["line"] == 9
    assert main["metadata"]["origin"] == "program"
    assert any(edge["target"] and edge["target"].endswith(":helper") for edge in data["edges"])


def _get(server, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{server.server_address[1]}{path}") as reply:
        return reply.read().decode()


def test_serve_lists_files_and_shows_source_from_the_code_map(tool):
    import xray.serve as serve_module

    server = serve_module.make_server(tool, graph_data(Path(tool), functions=True), port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        files = json.loads(_get(server, "/api/files?cmd=" + urllib.request.quote(str(tool))))["files"]
        source_file = next(f for f in files if f.endswith("tool.c"))
        listing = _get(server, f"/api/file?path={urllib.request.quote(source_file)}&cmd={urllib.request.quote(str(tool))}")
        assert "function(s) compiled from this file" in listing and "int main(void)" in listing
        body = _get(server, f"/api/source?name=helper&cmd={urllib.request.quote(str(tool))}")
        assert "    return x + 1;" in body.splitlines()  # plain lines: the page numbers them itself
    finally:
        server.shutdown()


def test_report_shows_the_code_map(tool):
    from xray.report import report_lines

    text = "\n".join(report_lines(tool))
    assert "Code map of" in text and "Program: 1 file(s)" in text
