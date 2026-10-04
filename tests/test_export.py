import json
import os
import subprocess
import sys
from pathlib import Path

from xray.export import export_data

REPO = Path(__file__).resolve().parent.parent


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

    return path


def run_xray(cwd, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)

    return subprocess.run(
        [sys.executable, "-m", "xray", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_python_file_export(tmp_path):
    source = write(tmp_path / "a.py", "import os\n\n\ndef f():\n    pass\n")

    data = export_data(source)

    assert data["file"] == str(source.resolve())
    assert data["kind"] == "python"
    assert data["analyzer"] == "python"
    assert [s["name"] for s in data["symbols"]] == ["f"]
    assert {
        "source": str(source.resolve()),
        "target": "os",
        "kind": "imports",
        "status": "external",
    } in data["edges"]


def test_shell_script_export(tmp_path):
    script = write(tmp_path / "tool", "#!/bin/sh\nnosuchcmd_xyz\n")

    data = export_data(script)

    assert data["kind"] == "shell"
    assert data["analyzer"] == "shell"
    assert data["symbols"] == []
    assert data["edges"] == [
        {
            "source": str(script.resolve()),
            "target": "nosuchcmd_xyz",
            "kind": "runs",
            "status": "unresolved",
        }
    ]


def test_unknown_file_has_no_analyzer(tmp_path):
    other = write(tmp_path / "notes.txt", "plain text\n")

    data = export_data(other)

    assert data["analyzer"] is None
    assert data["symbols"] == []
    assert data["edges"] == []


def test_export_is_json_serializable(tmp_path):
    source = write(tmp_path / "a.py", "def f():\n    pass\n")

    assert json.loads(json.dumps(export_data(source)))["kind"] == "python"


def test_cli_json_output_is_pure_json(tmp_path):
    source = write(tmp_path / "a.py", "import os\n")

    result = run_xray(tmp_path, str(source), "--json")

    assert result.returncode == 0
    assert result.stdout.lstrip().startswith("{")
    assert json.loads(result.stdout)["analyzer"] == "python"
    assert "XRAY" not in result.stdout


def test_cli_json_errors_go_to_stderr(tmp_path):
    result = run_xray(tmp_path, "missing_cmd_xyz", "--json")

    assert result.returncode == 3
    assert result.stdout == ""
    assert "Error:" in result.stderr
