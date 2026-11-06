import json

import pytest

from xray.errors import CLIError
from xray.evidencestore import EvidenceStore
from xray.scan import run_reach, run_scan


@pytest.fixture
def machine(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "helper").write_text("#!/bin/sh\necho hi\n")
    (bin_dir / "tool").write_text("#!/bin/sh\nhelper\n")
    (bin_dir / "other").write_text("#!/bin/sh\necho other\n")
    for path in bin_dir.iterdir():
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    return bin_dir, tmp_path / "store.sqlite"


def test_scan_then_reach_finds_the_chain(machine, capsys):
    bin_dir, store = machine

    assert run_scan([str(bin_dir), "--store", str(store), "--no-packages", "--quiet", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["programs"] == 3

    assert run_reach(["helper", "--store", str(store), "--json"]) == 0
    found = json.loads(capsys.readouterr().out)
    assert [item["command"] for item in found["programs"]] == ["tool"]
    assert [link["kind"] for link in found["programs"][0]["links"]] == ["runs", "resolves_to"]
    assert found["programs"][0]["links"][0]["evidence"][0]["line"] == 2


def test_reach_with_nothing_found_exits_one(machine, capsys):
    bin_dir, store = machine
    run_scan([str(bin_dir), "--store", str(store), "--no-packages", "--quiet"])
    capsys.readouterr()

    assert run_reach(["no-such-thing", "--store", str(store)]) == 1
    assert "Not found is not proof of absence" in capsys.readouterr().out


def test_reach_needs_a_scan(tmp_path):
    with pytest.raises(CLIError, match="xray scan"):
        run_reach(["x", "--store", str(tmp_path / "empty.sqlite")])


def test_second_scan_reads_unchanged_files_from_the_store(machine, capsys):
    bin_dir, store = machine
    run_scan([str(bin_dir), "--store", str(store), "--no-packages", "--quiet"])
    capsys.readouterr()

    run_scan([str(bin_dir), "--store", str(store), "--no-packages", "--quiet", "--json"])
    report = json.loads(capsys.readouterr().out)

    assert report["cache"]["misses"] == 0
    assert report["cache"]["hits"] > 0


def test_changed_file_is_read_again_and_hashed(machine, capsys):
    bin_dir, store = machine
    run_scan([str(bin_dir), "--store", str(store), "--no-packages", "--quiet"])
    with EvidenceStore(store) as opened:
        before = opened.sha256(str((bin_dir / "tool").resolve()))

    (bin_dir / "tool").write_text("#!/bin/sh\nother\n")
    run_scan([str(bin_dir), "--store", str(store), "--no-packages", "--quiet"])
    capsys.readouterr()
    with EvidenceStore(store) as opened:
        after = opened.sha256(str((bin_dir / "tool").resolve()))

    assert before and after and before != after
    assert run_reach(["other", "--store", str(store), "--json"]) == 0
    assert [item["command"] for item in json.loads(capsys.readouterr().out)["programs"]] == ["tool"]
