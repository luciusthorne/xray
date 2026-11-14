import hashlib
import json
import shutil
import struct

import pytest

from xray import asar, electron
from xray.codeview import code_lines

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="JavaScript analysis needs Node.js")


def make_asar(path, files, unpacked=(), raw_names=()):
    """Write an asar archive: files maps "dir/name" to bytes; names in `unpacked` go to path.unpacked/."""

    tree = {}
    data = b""
    for name, content in files.items():
        node = tree
        parts = name.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {"files": {}})["files"]
        entry = {"size": len(content),
                 "integrity": {"algorithm": "SHA256", "hash": hashlib.sha256(content).hexdigest()}}
        if name in unpacked:
            entry["unpacked"] = True
            target = path.parent / (path.name + ".unpacked") / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        else:
            entry["offset"] = str(len(data))
            data += content
        node[parts[-1]] = entry
    for name, content in raw_names:
        tree[name] = {"size": len(content), "offset": str(len(data))}
        data += content
    index = json.dumps({"files": tree}).encode()
    padded = index + b"\0" * (-len(index) % 4)
    payload = struct.pack("<I", len(index)) + padded
    header = struct.pack("<I", len(payload)) + payload
    path.write_bytes(struct.pack("<II", 4, len(header)) + header + data)
    return path


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XRAY_CACHE_DIR", str(tmp_path / "cache"))


MAIN = b"""const path = require('path');
function helper(x) {
  return x + 1;
}
function start() {
  return helper(2);
}
start();
"""


def test_reads_members_unpacked_files_and_integrity(tmp_path):
    archive = make_asar(tmp_path / "app.asar", {
        "package.json": b'{"name": "demo", "version": "1.0", "main": "main.js"}',
        "main.js": MAIN,
        "node_modules/addon/binding.node": b"\x7fELF native",
    }, unpacked={"node_modules/addon/binding.node"})

    assert asar.is_asar(archive)
    names = [m.name for m in asar.members(archive)]
    assert names == ["package.json", "main.js", "node_modules/addon/binding.node"]
    assert asar.read(archive, "main.js") == MAIN
    assert asar.read(archive, "node_modules/addon/binding.node") == b"\x7fELF native"
    assert asar.verified(archive, asar.member(archive, "main.js")) is True


def test_integrity_mismatch_is_reported(tmp_path):
    archive = make_asar(tmp_path / "app.asar", {"main.js": MAIN})
    content = archive.read_bytes()
    archive.write_bytes(content.replace(b"helper(2)", b"helper(3)"))

    assert asar.verified(archive, asar.member(archive, "main.js")) is False


def test_unsafe_member_names_are_refused(tmp_path):
    archive = make_asar(tmp_path / "evil.asar", {"main.js": MAIN},
                        raw_names=[("../../escape.js", b"bad"), ("/etc/passwd", b"bad")])

    assert [m.name for m in asar.members(archive)] == ["main.js"]
    extracted = asar.extract(archive, "main.js")
    assert (tmp_path / "cache") in extracted.parents
    assert extracted.read_bytes() == MAIN


def test_not_an_asar(tmp_path):
    other = tmp_path / "data.bin"
    other.write_bytes(b"\x00" * 64)
    assert not asar.is_asar(other)
    with pytest.raises(asar.AsarError):
        asar.members(other)


def test_launcher_script_leads_to_the_app_and_named_archives(tmp_path):
    make_asar(tmp_path / "app.asar", {
        "package.json": b'{"name": "loader", "main": "main.js"}',
        "main.js": b"const real = path.join(dir, 'real.asar');\nrequire(real);\n",
    })
    make_asar(tmp_path / "real.asar", {"package.json": b'{"name": "real"}', "main.js": MAIN})
    launcher = tmp_path / "demo"
    launcher.write_text(f"#!/bin/sh\nexec electron {tmp_path / 'app.asar'} \"$@\"\n")
    launcher.chmod(0o755)

    app = electron.find_app(launcher)

    assert app is not None
    assert [part.root.name for part in app.parts] == ["app.asar", "real.asar"]
    assert "line 2 passes" in app.how
    assert "names 'real.asar' (found by name)" in app.parts[1].how
    shown = "\n".join(electron.overview_lines(app))
    assert "Electron app: loader" in shown
    assert "real.asar" in shown


def test_electron_binary_finds_resources_app(tmp_path):
    (tmp_path / "resources").mkdir()
    make_asar(tmp_path / "resources" / "app.asar", {"package.json": b'{"name": "bundled"}', "index.js": MAIN})
    binary = tmp_path / "Bundled"
    binary.write_bytes(b"\x7fELF" + b"\0" * 60)
    (tmp_path / "v8_context_snapshot.bin").write_bytes(b"")

    app = electron.find_app(binary)

    assert app is not None and app.name == "bundled"
    assert app.main.entry() == "index.js"
    assert app.launcher == binary


def test_plain_scripts_and_binaries_are_not_apps(tmp_path):
    script = tmp_path / "plain"
    script.write_text("#!/bin/sh\nexec /bin/true\n")
    binary = tmp_path / "tool"
    binary.write_bytes(b"\x7fELF" + b"\0" * 60)
    assert electron.find_app(script) is None
    assert electron.find_app(binary) is None


def test_code_map_lists_own_code_packages_and_native_addons(tmp_path):
    archive = make_asar(tmp_path / "app.asar", {
        "package.json": b'{"name": "demo", "main": "main.js"}',
        "main.js": MAIN,
        "node_modules/@scope/lib/index.js": b"module.exports = 1;\n",
        "node_modules/addon/binding.node": b"\x7fELF",
    })

    text = "\n".join(code_lines(archive))

    assert "main.js  (" in text and "entry" in text
    assert "@scope/lib  (1 files" in text
    assert "Native addons (1)" in text and "node_modules/addon/binding.node" in text


def test_code_file_shows_source_and_integrity(tmp_path):
    archive = make_asar(tmp_path / "app.asar", {"package.json": b"{}", "main.js": MAIN})

    text = "\n".join(code_lines(archive, "main.js"))

    assert "Integrity: matches the SHA-256" in text
    assert "    2  function helper(x) {" in text


@needs_node
def test_code_function_and_callgraph(tmp_path):
    archive = make_asar(tmp_path / "app.asar", {"package.json": b'{"main": "main.js"}', "main.js": MAIN})
    app = electron.find_app(archive)

    shown = electron.code_lines(app, "helper")
    assert shown[0].startswith("helper (function)") and "lines 2–4" in shown[0]
    assert any("return x + 1;" in line for line in shown)

    graph = "\n".join(electron.callgraph_lines(app, "helper"))
    assert "← start" in graph

    missing = electron.code_lines(app, "nowhere")
    assert missing[0].startswith(electron.NOT_FOUND)


@needs_node
def test_minified_function_is_cut_by_offsets(tmp_path):
    bundle = b"var a=1;" * 400 + b"function picked(n){return n*2}" + b"function other(){return picked(1)}"
    archive = make_asar(tmp_path / "app.asar", {"package.json": b'{"main": "bundle.js"}', "bundle.js": bundle})
    app = electron.find_app(archive)

    shown = electron.code_lines(app, "picked")

    assert "Bundled or minified file" in shown[1]
    assert shown[-1] == "function picked(n){return n*2}"
