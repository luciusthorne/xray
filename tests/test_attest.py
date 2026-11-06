import json
import shutil

import pytest

from xray import attest
from xray.driftverbs import run_attest

needs_ssh = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")


@pytest.fixture
def signed(tmp_path):
    key = attest.keygen(tmp_path / "key")
    program = tmp_path / "tool"
    program.write_text("#!/bin/sh\necho hi\n")
    contract = tmp_path / "tool.contract"
    contract.write_text(f"xray-contract 1\nprogram {program}\n\n[exec]\n{program}\n")
    written = attest.sign(attest.contract_statement(contract), tmp_path / "tool.intoto.json", key)
    return tmp_path, key, contract, program, written


@needs_ssh
def test_statement_shape_and_verification(signed):
    _tmp_path, _key, _contract, program, written = signed
    data = json.loads(written[0].read_text())

    assert data["_type"] == "https://in-toto.io/Statement/v1"
    assert data["predicateType"].endswith("/contract/v1")
    assert [item["name"] for item in data["subject"]] == ["tool.contract", str(program)]
    ok, messages = attest.verify(written[0], written[2])
    assert ok and any(message.startswith("unchanged: tool.contract") for message in messages)


@needs_ssh
def test_a_changed_subject_or_statement_fails(signed):
    _tmp_path, _key, _contract, program, written = signed

    program.write_text("#!/bin/sh\ncurl -s x\n")
    ok, messages = attest.verify(written[0], written[2])
    assert not ok and any(message.startswith("CHANGED since it was attested") for message in messages)

    forged = json.loads(written[0].read_text())
    forged["predicate"]["contract"] += "\n# edited"
    written[0].write_text(json.dumps(forged))
    ok, _ = attest.verify(written[0], written[2])
    assert not ok


@needs_ssh
def test_another_key_does_not_verify(signed, tmp_path):
    _base, _key, _contract, _program, written = signed
    other = attest.keygen(tmp_path / "other")
    public = (tmp_path / "other.pub").read_text().split()
    signers = tmp_path / "other.signers"
    signers.write_text(f'xray namespaces="{attest.NAMESPACE}" {public[0]} {public[1]}\n')
    del other

    ok, _ = attest.verify(written[0], signers)
    assert not ok


@needs_ssh
def test_cli_profile_and_report(tmp_path, capsys):
    key = tmp_path / "key"
    assert run_attest(["keygen", "--key", str(key)]) == 0
    report = tmp_path / "drift.json"
    report.write_text(json.dumps({"gains": []}))
    assert run_attest(["report", str(report), "-o", str(tmp_path / "r.intoto.json"), "--key", str(key)]) == 0
    assert run_attest(["profile", "/bin/sh", "-o", str(tmp_path / "p.intoto.json"), "--key", str(key)]) == 0
    assert json.loads((tmp_path / "p.intoto.json").read_text())["predicate"]["profiles"]
    capsys.readouterr()
    assert run_attest(["verify", str(tmp_path / "r.intoto.json"), "--signers", str(tmp_path / "r.intoto.json.signers")]) == 0
    assert capsys.readouterr().out.startswith("VERIFIED")
