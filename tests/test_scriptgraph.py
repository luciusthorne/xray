"""Shell script call graphs: functions calling functions, commands per function, line numbers."""

import subprocess
import sys
from pathlib import Path

from xray.scriptgraph import TOP, callgraph_lines, shell_graph

REPO = Path(__file__).resolve().parents[1]

SCRIPT = """#!/bin/sh
. ./lib.sh

help() {
    cat <<EOF
usage: { not code } "quotes ' here
EOF
}

fetch() {
    curl -s "$1" | grep x
}

work() {
    data=$(fetch "$1")
    sudo install -m 644 "$data" /tmp/x
    help
}

unused() {
    echo never
}

work "$@"
"""


def _script(tmp_path):
    path = tmp_path / "tool"
    path.write_text(SCRIPT)
    path.chmod(0o755)
    return path


def test_functions_calls_commands_and_spans(tmp_path):
    graph = shell_graph(_script(tmp_path))

    assert graph.functions["help"] == (4, 8)  # the heredoc's braces and quotes do not stretch it
    assert graph.functions["work"] == (14, 18)
    assert graph.calls["work"] == {"fetch": [15], "help": [17]}  # $(...) counts, inside work
    assert set(graph.commands["work"]) == {"sudo", "install"}  # sudo and the command it runs
    assert set(graph.commands["fetch"]) == {"curl", "grep"}
    assert graph.calls[TOP] == {"work": [24]}
    assert graph.sources[TOP] == {"./lib.sh": [2]}


def test_text_views(tmp_path):
    graph = shell_graph(_script(tmp_path))

    whole = "\n".join(callgraph_lines(graph, "tool"))
    assert "→ fetch  (defined at line 10; called at line 15)" in whole
    assert "Not called by any function or the top level: unused" in whole

    one = "\n".join(callgraph_lines(graph, "tool", focus="fetch"))
    assert "← work  (line 15)" in one and "curl: line 11" in one
    assert "No function named" in callgraph_lines(graph, "tool", focus="nope")[0]


def test_cli(tmp_path):
    path = _script(tmp_path)
    result = subprocess.run([sys.executable, "-m", "xray.cli", str(path), "--callgraph", "work"],
                            cwd=REPO, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "→ fetch" in result.stdout and "← (top level)" in result.stdout


# -- other languages: calls found by name ------------------------------------

import pytest

from xray.scriptgraph import _blank_comments_and_strings, symbol_graph

PERL = """#!/usr/bin/perl
use strict;

sub helper ($);
sub main_loop ();

sub helper ($)
{
    my ($x) = @_;
    print "helper() in a string\\n";   # helper() in a comment
    return $x + 1;
}

sub main_loop ()
{
    my %h = (helper => 1);
    my $v = helper (1);
    &helper(2);
    return $h{helper};
}

main_loop;
exit 0;
"""

JS = """#!/usr/bin/env node
function helper(x) {
  // helper(1) in a comment
  return x + 1;
}
function run() {
  const s = "helper(2) in a string";
  return helper(3);
}
run();
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    path.chmod(0o755)
    return path


def test_blanking_keeps_columns_and_drops_strings_and_comments():
    out = _blank_comments_and_strings(['x = "f(1)"  # f(2)', "y = f(3)"], "perl")
    assert out[0].rstrip() == 'x = "    "' and out[1] == "y = f(3)"
    assert len(out[0]) == len('x = "f(1)"  # f(2)')


def test_perl_calls_with_and_without_parentheses(tmp_path):
    graph = symbol_graph(_write(tmp_path, "tool", PERL), "perl")
    if graph is None:
        pytest.skip("Perl analyzer found no subs here")
    assert graph.functions["helper"][0] == 7  # the definition, not the forward declaration on line 4
    assert graph.calls["main_loop"] == {"helper": [17, 18]}  # helper (1) and &helper(2); not the hash keys
    assert graph.calls[TOP] == {"main_loop": [22]}  # bare call


def test_javascript_calls(tmp_path):
    graph = symbol_graph(_write(tmp_path, "tool.js", JS), "javascript")
    if graph is None:
        pytest.skip("JavaScript analyzer found no functions here")
    assert graph.calls["run"] == {"helper": [8]}  # not the string on line 7 or the comment on line 3
    assert graph.calls[TOP] == {"run": [10]}


RUBY = '#!/usr/bin/env ruby\ndef helper(x)\n  x + 1\nend\n\ndef run\n  s = "helper(9)"\n  helper 2\n  helper(3)\nend\n\nrun\n'
LUA = "#!/usr/bin/env lua\nlocal function helper(x)\n  return x + 1\nend\n\nfunction run()\n  -- helper(1)\n  return helper(2)\nend\n\nrun()\n"


@pytest.mark.parametrize("name, kind, text, run_calls", [
    ("tool.rb", "ruby", RUBY, {"helper": [8, 9]}),  # "helper 2" without parentheses; not the string
    ("tool.lua", "lua", LUA, {"helper": [8]}),       # not the comment
])
def test_ruby_and_lua_calls(tmp_path, name, kind, text, run_calls):
    graph = symbol_graph(_write(tmp_path, name, text), kind)
    if graph is None:
        pytest.skip(f"{kind} analyzer unavailable here")
    assert graph.calls["run"] == run_calls
    assert TOP in graph.calls and "run" in graph.calls[TOP]
