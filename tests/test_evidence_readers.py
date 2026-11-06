import shutil

import pytest

from xray.evidence import build_evidence_graph


def graph_of(path):
    return build_evidence_graph(str(path), max_depth=1, packages=False)


@pytest.mark.skipif(not shutil.which("ruby"), reason="Ruby is required")
def test_ruby_requires_and_commands(tmp_path):
    (tmp_path / "helper.rb").write_text("def x; end\n")
    main = tmp_path / "main.rb"
    main.write_text('require_relative "helper"\nsystem("git", "status")\nout = `uname -r`\n')

    graph = graph_of(main)
    root = str(main.resolve())

    link = graph.links[(root, str((tmp_path / "helper.rb").resolve()), "imports")]
    assert (link.evidence[0].method, link.evidence[0].line) == ("ruby-import", 1)
    assert graph.links[(root, "command:git", "runs")].evidence[0].line == 2
    assert graph.links[(root, "command:uname", "runs")].evidence[0].line == 3


@pytest.mark.skipif(not shutil.which("node"), reason="Node is required")
def test_javascript_imports_and_child_process(tmp_path):
    (tmp_path / "lib.js").write_text("module.exports = 1;\n")
    main = tmp_path / "main.js"
    main.write_text("const lib = require('./lib');\nconst cp = require('child_process');\ncp.execSync('ls -l');\n")

    graph = graph_of(main)
    root = str(main.resolve())

    assert (root, str((tmp_path / "lib.js").resolve()), "imports") in graph.links
    assert graph.links[(root, "command:ls", "runs")].evidence[0].line == 3


def test_c_includes_resolve_local_and_system_headers(tmp_path):
    from xray.treesitter_analyzers import parser_available

    if not parser_available("c"):
        pytest.skip("the Tree-sitter C parser is required")
    (tmp_path / "local.h").write_text("int x;\n")
    main = tmp_path / "t.c"
    main.write_text('#include <stdio.h>\n#include "local.h"\nint main(void){return 0;}\n')

    graph = graph_of(main)
    root = str(main.resolve())

    link = graph.links[(root, str((tmp_path / "local.h").resolve()), "includes")]
    assert (link.evidence[0].method, link.evidence[0].line) == ("c-include", 2)
    if shutil.os.path.exists("/usr/include/stdio.h"):
        assert (root, "/usr/include/stdio.h", "includes") in graph.links
