from xray.chain import chain_lines


def sh(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)

    return path


def test_sourced_files_are_not_listed(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "chainb", "echo hi\n")
    sh(tmp_path / "lib.sh", "x=1\n")
    tool = sh(tmp_path / "tool", ". ./lib.sh\nchainb\n")
    monkeypatch.setenv("PATH", str(bindir))

    assert chain_lines(tool) == [
        f"{tool.resolve()} [shell]",
        f"└── chainb -> {b.resolve()} [shell]",
    ]
