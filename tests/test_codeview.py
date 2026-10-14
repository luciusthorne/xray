import xray.codeview as cv


def script(tmp_path, kind="#!/bin/sh\n", body="echo hi\nf() {\n  :\n}\n"):
    path = tmp_path / "tool"
    path.write_text(kind + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def test_script_is_printed_with_line_numbers(tmp_path):
    lines = cv.code_lines(script(tmp_path))

    assert lines[0] == "    1  #!/bin/sh"
    assert lines[2] == "    3  f() {"


def test_shell_function_starts_at_its_line(tmp_path):
    lines = cv.code_lines(script(tmp_path), "f")

    assert lines[0] == "    3  f() {"


def test_unknown_script_function(tmp_path):
    assert cv.code_lines(script(tmp_path), "nope") == [
        "No function named nope in this script"
    ]


def test_elf_dispatches_and_adds_assembly(tmp_path, monkeypatch):
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(cv, "source_lines", lambda p, n, say=None: [f"SRC {n}"])
    monkeypatch.setattr(cv, "function_lines", lambda p, n: [f"ASM {n}"])
    monkeypatch.setattr(cv, "files_lines", lambda p, n, say=None: ["FILES"])

    assert cv.code_lines(binary, "f") == ["SRC f"]
    assert cv.code_lines(binary, "f", asm=True) == [
        "SRC f", "", "Disassembly:", "ASM f",
    ]
    assert cv.code_lines(binary) == ["FILES"]
    assert cv.code_lines(binary, "x.c") == ["FILES"]
