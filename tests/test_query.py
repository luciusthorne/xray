import json

import pytest

from xray import caplog, query
from xray.driftverbs import run_query
from xray.scan import run_scan


def test_log_tables_and_read_only(tmp_path):
    log = tmp_path / "log.jsonl"
    entry = {"log_version": 1, "seq": 0, "package": "demo", "version": "1.0-1", "arch": "x86_64",
             "archive": "demo.pkg.tar.zst", "archive_sha256": "a" * 64, "prev": caplog.GENESIS,
             "files": {"usr/lib/libdemo.so.1": {"kind": "elf", "sha256": "b", "needed": ["libc.so.6"],
                                                "classes": {"shell": ["system"]}, "ifuncs": 1, "constructors": 1}}}
    entry["hash"] = caplog.entry_hash(entry)
    log.write_text(json.dumps(entry) + "\n")
    db = query.load_log(log)

    names, rows = query.run(db, "SELECT package, path, symbol FROM calls WHERE class = 'shell'")
    assert names == ["package", "path", "symbol"] and rows == [("demo", "usr/lib/libdemo.so.1", "system")]
    assert query.run(db, "WITH x AS (SELECT library FROM needs) SELECT * FROM x")[1] == [("libc.so.6",)]
    for bad in ("DELETE FROM files", "SELECT 1; DROP TABLE files"):
        with pytest.raises(ValueError):
            query.run(db, bad)


def test_store_queries_after_a_scan(tmp_path, monkeypatch, capsys):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("helper", "echo hi\n"), ("tool", "helper\ncurl -s x\n")):
        (bin_dir / name).write_text("#!/bin/sh\n" + body)
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin")
    store = tmp_path / "store.sqlite"
    run_scan([str(bin_dir), "--store", str(store), "--no-packages", "--quiet"])
    capsys.readouterr()

    assert run_query(["--store", str(store), "--json",
                      "SELECT DISTINCT command FROM reach WHERE kind = 'command' AND label = 'curl'"]) == 0
    assert json.loads(capsys.readouterr().out)["rows"] == [{"command": "tool"}]
    with open(store, "rb"):
        pass
    assert run_query(["--examples"]) == 0
