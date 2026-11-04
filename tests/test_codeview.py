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


def test_stripped_elf_falls_back_to_bounded_disassembly(tmp_path, monkeypatch):
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(
        cv, "files_lines", lambda p, n, say=None: [
            "No function names in this binary (it has no .gnu_debugdata)"
        ]
    )
    monkeypatch.setattr(cv, "assembly_lines", lambda p, name=None: ["    1000: ret"])

    lines = cv.code_lines(binary)

    assert lines[0].startswith("No function names")
    assert "showing ELF disassembly instead" in lines[2]
    assert lines[-1] == "    1000: ret"


def test_unavailable_named_source_uses_full_disassembly_if_label_missing(
    tmp_path, monkeypatch
):
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(
        cv, "source_lines", lambda p, n, say=None: ["Source not available: package"]
    )
    monkeypatch.setattr(
        cv,
        "assembly_lines",
        lambda p, name=None: ["No disassembly label named main"]
        if name
        else ["00001000 <entry>", "  1000: ret"],
    )

    lines = cv.code_lines(binary, "main")

    assert "The requested symbol has no label" in lines[2]
    assert lines[-1] == "  1000: ret"


def test_unowned_elf_source_is_classified_as_unavailable():
    assert cv._source_unavailable([
        "No installed package owns this file, so there is no source package"
    ])


def test_unknown_elf_function_uses_bounded_disassembly(tmp_path, monkeypatch):
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(
        cv, "source_lines", lambda p, n, say=None: [f"Unknown function: {n}"]
    )
    monkeypatch.setattr(
        cv,
        "assembly_lines",
        lambda p, name=None: ["No disassembly label named main"]
        if name
        else ["  1000: ret"],
    )

    lines = cv.code_lines(binary, "main")

    assert lines[0] == "Unknown function: main"
    assert "showing bounded ELF disassembly" in lines[2]
    assert lines[-1] == "  1000: ret"


def test_code_without_function_lists_debuginfod_names(tmp_path, monkeypatch):
    binary = tmp_path / "prog"
    binary.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(
        cv,
        "files_lines",
        lambda p, n, say=None: ["Package coreutils has no cached source"],
    )
    monkeypatch.setattr("xray.debuginfod.configured", lambda: True)
    monkeypatch.setattr(
        "xray.debuginfod.function_names",
        lambda _path: ("error", "main", "sort_files"),
    )

    lines = cv.code_lines(binary)

    assert "Functions available from debuginfod (3):" in lines
    header = lines.index("Functions available from debuginfod (3):")
    assert lines[header + 1] == "- main"
    assert lines[-1] == "Read one with --code <function name>."
