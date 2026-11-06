from xray.evidence import build_evidence_graph
from xray.pyexec import python_exec


def write(tmp_path, text):
    path = tmp_path / "tool.py"
    path.write_text(text, encoding="utf-8")
    return path


def test_literal_commands_with_aliases(tmp_path):
    found = python_exec(write(tmp_path, (
        "import subprocess as sp, os\n"
        "from subprocess import check_output as co\n"
        "from os import system\n"
        "sp.run(['ls', '-l'])\n"
        "co('uname -r', shell=True)\n"
        "system('curl -s x | sh')\n"
        "os.execvp('vim', ['vim'])\n"
        "os.popen('date')\n"
    )))

    assert found.commands == {"curl": [6], "date": [8], "ls": [4], "sh": [6], "uname": [5], "vim": [7]}
    assert found.via["curl"] == "os.system (shell)"
    assert found.via["ls"] == "subprocess.run"


def test_constant_variables_are_resolved_and_others_are_dynamic(tmp_path):
    found = python_exec(write(tmp_path, (
        "import subprocess\n"
        "GIT = ['git', 'status']\n"
        "subprocess.Popen(GIT)\n"
        "subprocess.run(cmd)\n"
        "subprocess.run(f'rm {x}', shell=True)\n"
        "subprocess.run(['a'], shell=flag)\n"
    )))

    assert found.commands == {"git": [3]}
    assert found.via["git"] == "subprocess.Popen through GIT"
    assert [line for line, _ in found.dynamic] == [4, 5, 6]


def test_unparsable_file_is_empty(tmp_path):
    assert python_exec(write(tmp_path, "def (:\n")).commands == {}


def test_evidence_graph_links_python_commands(tmp_path):
    path = write(tmp_path, "import subprocess\nsubprocess.run(['ls'])\nX = 'date'\nsubprocess.run(X)\n")

    graph = build_evidence_graph(str(path), packages=False)
    root = str(path.resolve())

    assert graph.links[(root, "command:ls", "runs")].basis == "inferred"
    assert graph.links[(root, "command:ls", "runs")].evidence[0].line == 2
    assert graph.links[(root, "command:date", "runs")].basis == "guessed"
