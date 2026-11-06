import pytest

from xray.pytaint import python_taint
from xray.shtaint import shell_taint
from xray.taint import analyze, report_lines, severity


def sh(text, **options):
    return shell_taint("/tmp/x.sh", text="#!/bin/sh\n" + text, **options)


def sinks(result):
    return [(item["sink"], item["line"], item["sources"]) for item in result.findings]


def test_argument_reaching_eval_through_a_variable_and_a_function():
    result = sh('name="$1"\nrun() {\n  local what="$1"\n  eval "echo $what"\n}\nrun "$name"\n')

    assert sinks(result) == [("eval", 5, ["argv"])]


def test_single_quotes_and_arithmetic_are_not_input():
    result = sh("eval 'echo $1'\nx=$(( $# + 1 ))\neval \"echo $x\"\n")

    assert result.findings == []


def test_read_and_network_downloads_are_sources():
    result = sh('read -r line\nsh -c "$line"\nscript=$(curl -fsSL https://example.invalid/i.sh)\nbash -c "$script"\n')

    assert sinks(result) == [("sh -c", 3, ["stdin"]), ("sh -c", 5, ["network"])]


def test_for_loops_and_getopts_carry_arguments():
    result = sh('for f in "$@"; do . "$f"; done\nwhile getopts c: o; do cmd=$OPTARG; done\n$cmd\n')

    assert ("source", 2, ["argv"]) in sinks(result)
    assert ("command", 4, ["argv"]) in sinks(result)


def test_array_command_name_comes_from_its_first_element():
    result = sh('cmd=(busctl --user call "$1")\n"${cmd[@]}"\nother=("$1" -x)\n"${other[@]}"\n')

    assert sinks(result) == [("command", 5, ["argv"])]
    assert result.calls == [("busctl", [[], [], ["argv"]], 3)]


def test_unassigned_variables_are_environment_and_eval_assignments_are_not():
    result = sh('eval "made=$(date)"\neval "$made"\neval "$FROM_ENV"\n')

    assert sinks(result) == [("eval", 4, ["env:FROM_ENV"])]


def test_exported_tainted_variables_are_recorded():
    result = sh('export TARGET="$1"\nhelper\n')

    assert result.exported == {"TARGET": {"argv"}}


def py(text, **options):
    return python_taint("/tmp/x.py", text=text, **options)


def test_python_sources_sinks_and_sanitizers():
    findings, calls = py(
        "import os, sys, shlex, subprocess, pickle, requests\n"
        "target = sys.argv[1]\n"
        "os.system('ls ' + target)\n"
        "subprocess.run('ls ' + shlex.quote(target), shell=True)\n"
        "body = requests.get('https://example.invalid').text\n"
        "exec(body)\n"
        "pickle.loads(sys.stdin.buffer.read())\n"
        "subprocess.run(['grep', target, 'f'])\n"
        "prog = shutil.which('tool') if any(x == target for x in sys.argv) else None\n"
        "subprocess.run([prog, '-v'])\n"
    )

    assert [(item["sink"], item["line"], item["sources"]) for item in findings] == [
        ("shell", 3, ["argv"]), ("exec", 6, ["network"]), ("pickle", 7, ["stdin"]),
    ]
    assert calls == [("grep", [["argv"], []], 8)]


def test_python_flow_through_parameters_and_returns():
    findings, _ = py(
        "import os, sys\n"
        "def build(x):\n"
        "    return 'echo ' + x\n"
        "def run(command):\n"
        "    os.popen(command)\n"
        "run(build(os.environ['NAME']))\n"
    )

    assert [(item["sink"], item["line"], item["sources"]) for item in findings] == [("shell", 5, ["env:NAME"])]


def test_severity_follows_trust_boundaries():
    assert severity("eval", ["network"]) == "high"
    assert severity("eval", ["argv"]) == "medium"
    assert severity("eval", ["argv"], privileged=True) == "high"
    assert severity("command", ["argv"]) == "info"
    assert severity("eval", ["env:X"]) == "low"


def test_cross_language_chain_from_shell_into_python(tmp_path):
    tool = tmp_path / "tool"
    tool.write_text('#!/bin/sh\nname="$1"\npython3 "$(dirname "$0")/helper.py" "$name"\n')
    helper = tmp_path / "helper.py"
    helper.write_text("import subprocess, sys\nsubprocess.run('ls ' + sys.argv[1], shell=True)\n")
    for path in (tool, helper):
        path.chmod(0o755)

    report = analyze(str(tool))
    finding = next(item for item in report.findings if item["file"] == str(helper))

    assert (finding["sink"], finding["line"], finding["severity"]) == ("shell", 2, "medium")
    assert finding["chain"][0]["file"] == str(tool.resolve())
    assert finding["chain"][0]["line"] == 3
    text = "\n".join(report_lines(report))
    assert "via " in text and "helper.py:2" in text


def test_missing_command_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze(str(tmp_path / "nope"))


def test_arguments_are_followed_by_position(tmp_path):
    tool = tmp_path / "tool"
    tool.write_text('#!/bin/sh\npython3 "$(dirname "$0")/helper.py" safe-name "$1"\n')
    helper = tmp_path / "helper.py"
    helper.write_text(
        "import os, sys\n"
        "os.system('echo ' + sys.argv[1])\n"   # argument 1 is a fixed string: not a finding
        "os.system('echo ' + sys.argv[2])\n"   # argument 2 is the caller's $1: a finding
    )
    for path in (tool, helper):
        path.chmod(0o755)

    report = analyze(str(tool))
    lines = sorted(item["line"] for item in report.findings if item["file"] == str(helper))

    assert lines == [3]
    finding = next(item for item in report.findings if item["file"] == str(helper))
    assert "as argument 2" in finding["chain"][0]["detail"]


def test_positional_shell_arguments():
    result = sh('eval "$2"\neval "$1"\n', argv_labels=[[], ["argv"]])

    assert [(item["sink"], item["line"]) for item in result.findings] == [("eval", 2)]
