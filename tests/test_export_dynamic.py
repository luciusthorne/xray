from xray.export import export_data


def script(tmp_path, body):
    path = tmp_path / "tool"
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def test_variable_commands_add_a_note(tmp_path):
    data = export_data(script(tmp_path, 'ls\n$cmd x\neval "$y"\n'))

    assert data["notes"] == [
        "2 command(s) run through variables or eval (not resolved)"
    ]


def test_no_variable_commands_means_no_such_note(tmp_path):
    data = export_data(script(tmp_path, "ls\n"))

    assert data["notes"] == []


def test_both_notes_can_appear_together(tmp_path):
    data = export_data(script(tmp_path, "$cmd x\n"))

    assert len(data["notes"]) == 2
    assert data["notes"][0].startswith("no external commands found")
    assert data["notes"][1].startswith("1 command(s) run through")


def test_python_files_get_no_such_note(tmp_path):
    source = tmp_path / "a.py"
    source.write_text("import os\n", encoding="utf-8")

    assert export_data(source)["notes"] == []
