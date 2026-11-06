import shutil
import subprocess

import pytest

from xray.elftaint import calls_by_function, function_table, leads
from xray.taint import analyze

needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None or shutil.which("objdump") is None,
                               reason="needs gcc and objdump")

PROGRAM = r"""
#include <stdio.h>
#include <stdlib.h>
static void run(const char *cmd) { system(cmd); }
static int handle(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 1;
    run(line);
    return 0;
}
static int quiet(void) { return puts("ok"); }
int main(void) {
    const char *home = getenv("HOME");
    printf("%s\n", home ? home : "-");
    quiet();
    return handle();
}
"""


@pytest.fixture
def program(tmp_path, monkeypatch):
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    source = tmp_path / "t.c"
    source.write_text(PROGRAM)
    binary = tmp_path / "t"
    subprocess.run(["gcc", "-g", "-O0", "-o", binary, source], check=True)
    return binary


@needs_gcc
def test_branches_inside_a_function_are_not_calls(program):
    table, _ = function_table(program)
    calls = calls_by_function(program, table)

    assert [name for _, name, _ in calls["handle"]] == ["fgets", "run", "__stack_chk_fail"] or \
        [name for _, name, _ in calls["handle"]] == ["fgets", "run"]
    assert all(name != "handle" for _, name, _ in calls["handle"])


@needs_gcc
def test_input_followed_by_execution_is_a_lead_with_lines(program):
    found, how = leads(program)
    summary = {(lead.function, lead.source.symbol, lead.sink.symbol, tuple(lead.via)) for lead in found}

    assert ("handle", "fgets", "system", ("run",)) in summary
    assert ("main", "getenv", "system", ("handle", "run")) in summary
    lead = next(lead for lead in found if lead.function == "handle")
    assert lead.source.location.split(":")[1] == "7"
    assert lead.sink.location.split(":")[1] == "4"
    assert how == "symbols and line information from the binary"


@needs_gcc
def test_taint_reports_leads_for_a_compiled_program(program):
    report = analyze(str(program))
    details = [item["detail"] for item in report.findings if item["sink"] == "binary"]

    assert any(detail.startswith("in handle, fgets() is followed by system() via run") for detail in details)
    assert all(item["basis"] == "guessed" for item in report.findings if item["sink"] == "binary")


@needs_gcc
def test_a_program_without_execution_has_no_leads(tmp_path, monkeypatch):
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    source = tmp_path / "q.c"
    source.write_text('#include <stdio.h>\nint main(void){char b[9]; return fgets(b, 9, stdin) ? puts(b) : 1;}\n')
    subprocess.run(["gcc", "-g", "-o", tmp_path / "q", source], check=True)

    assert leads(tmp_path / "q")[0] == []
