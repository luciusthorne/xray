"""FDO dlopen metadata notes (.note.dlopen): libraries a program may load on demand."""

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from xray.contractgen import from_graph
from xray.elfscan import (
    NT_FDO_DLOPEN_METADATA,
    DlopenEntry,
    parse_dlopen_payload,
    read_dlopen_notes,
)
from xray.evidence import build_evidence_graph


def _note(payload, order="<", name=b"FDO\0", kind=NT_FDO_DLOPEN_METADATA):
    desc = payload + b"\0" * (-len(payload) % 4)
    return struct.pack(order + "III", len(name), len(desc), kind) + name + b"\0" * (-len(name) % 4) + desc


def _elf(notes, is64=True, little=True):
    """Minimal ELF: header, one SHT_NOTE section, section header table."""
    order = "<" if little else ">"
    header_size = 64 if is64 else 52
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1]) + b"\0" * 9
    body = notes
    note_offset = header_size
    shoff = note_offset + len(body)
    if is64:
        null = b"\0" * 64
        note = struct.pack(order + "IIQQQQIIQQ", 0, 7, 0, 0, note_offset, len(body), 0, 0, 4, 0)
        header = ident + struct.pack(order + "HHIQQQIHHHHHH", 3, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 2, 0)
    else:
        null = b"\0" * 40
        note = struct.pack(order + "IIIIIIIIII", 0, 7, 0, 0, note_offset, len(body), 0, 0, 4, 0)
        header = ident + struct.pack(order + "HHIIIIIHHHHHH", 3, 3, 1, 0, 0, shoff, 0, 52, 0, 0, 40, 2, 0)
    assert len(header) == header_size
    return header + body + null + note


ENTRY = [{"feature": "lzma", "description": "journal compression", "priority": "suggested",
          "soname": ["liblzma.so.5"]}]


@pytest.mark.parametrize("is64, little", [(True, True), (False, False)])
def test_notes_are_read_in_both_classes_and_byte_orders(tmp_path, is64, little):
    order = "<" if little else ">"
    notes = _note(json.dumps(ENTRY).encode(), order) + _note(b"ignored", order, name=b"GNU\0", kind=3)
    path = tmp_path / "lib.so"
    path.write_bytes(_elf(notes, is64, little))

    assert read_dlopen_notes(path) == (
        DlopenEntry("lzma", "suggested", ("liblzma.so.5",), "journal compression"),
    )


def test_malformed_payloads_are_skipped():
    assert parse_dlopen_payload(b"not json") == ()
    assert parse_dlopen_payload(b'{"soname": ["a.so"]}') == ()
    entries = parse_dlopen_payload(json.dumps([
        {"soname": []}, {"soname": "x.so"}, "junk", {"soname": ["ok.so.1"]},
    ]).encode() + b"\0\0")
    assert entries == (DlopenEntry("", "recommended", ("ok.so.1",), ""),)


def test_files_without_notes(tmp_path):
    (tmp_path / "text").write_text("hello")
    assert read_dlopen_notes(tmp_path / "text") == ()
    assert read_dlopen_notes(tmp_path / "missing") == ()
    (tmp_path / "short").write_bytes(b"\x7fELF\x02\x01")
    assert read_dlopen_notes(tmp_path / "short") == ()


PROGRAM = r'''
#include <stdint.h>
#define JSON "[{\"feature\":\"math\",\"description\":\"fast math\",\"priority\":\"suggested\",\"soname\":[\"libxray-not-here.so.9\",\"libm.so.6\"]}]"
#define PAD(n) (((n) + 3) & ~3)
struct note { uint32_t namesz, descsz, type; char name[4]; char desc[PAD(sizeof(JSON))]; };
__attribute__((used, aligned(4), section(".note.dlopen")))
static const struct note dlopen_note = { 4, PAD(sizeof(JSON)), 0x407c0c0a, "FDO", JSON };
int main(void) { return 0; }
'''


@pytest.mark.skipif(not (shutil.which("cc") and shutil.which("readelf")), reason="needs cc and readelf")
def test_compiled_program_gets_a_declared_dlopens_link(tmp_path):
    (tmp_path / "tool.c").write_text(PROGRAM)
    tool = tmp_path / "tool"
    subprocess.run(["cc", "-o", str(tool), str(tmp_path / "tool.c")], check=True)

    assert read_dlopen_notes(tool)[0].sonames == ("libxray-not-here.so.9", "libm.so.6")

    graph = build_evidence_graph(tool, max_depth=2)
    links = [link for link in graph.outgoing(str(tool.resolve())) if link.kind == "dlopens"]
    assert len(links) == 1
    link = links[0]
    assert link.basis == "declared"
    assert link.target == "soname:libm.so.6"  # the first soname that resolves
    assert "feature math, suggested" in link.evidence[0].detail
    resolved = [step for step in graph.outgoing(link.target) if step.kind == "resolves_to"]
    assert resolved and Path(resolved[0].target).name.startswith("libm")

    contract = from_graph(graph)
    assert any(Path(entry.value).name.startswith("libm") and "dlopen" in entry.comment for entry in contract.sections["load"])
