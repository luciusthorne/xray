import xray.command_analyzers as analyzers_module
from xray.chain import chain_lines
from xray.elfscan import ElfScan
from xray.overview import overview_lines


def write(path, text, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")

    path.chmod(mode)

    return path


def sh(path, body="echo hi\n"):
    return write(path, "#!/bin/sh\n" + body)


def test_libraries_can_be_hidden(tmp_path, monkeypatch):
    binary = write(tmp_path / "prog", b"\x7fELF" + bytes(60))

    monkeypatch.setattr(
        analyzers_module,
        "scan_elf",
        lambda path: ElfScan(needed=("libfoo.so.1",)),
    )
    monkeypatch.setattr(analyzers_module, "ldconfig_cache", lambda: {})

    assert chain_lines(binary, include_libraries=False) == [
        f"{binary.resolve()} [elf]"
    ]
    assert len(chain_lines(binary)) == 2


def test_shell_overview_ends_with_a_chain(tmp_path, monkeypatch):
    bindir = tmp_path / "fakebin"
    b = sh(bindir / "ovchainb", "ovchainc\n")
    c = sh(bindir / "ovchainc")
    tool = sh(tmp_path / "tool", "ovchainb\n")
    monkeypatch.setenv("PATH", str(bindir))

    lines = overview_lines(tool)

    assert "Chain:" in lines

    tail = lines[lines.index("Chain:") + 1:]

    assert tail == [
        f"{tool.resolve()} [shell]",
        f"└── ovchainb -> {b.resolve()} [shell]",
        f"    └── ovchainc -> {c.resolve()} [shell]",
    ]


def test_no_chain_when_nothing_is_run(tmp_path):
    tool = sh(tmp_path / "tool", "echo hi\n")

    assert "Chain:" not in overview_lines(tool)
