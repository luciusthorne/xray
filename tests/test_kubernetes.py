"""Kubernetes manifests from capability contracts."""

import json
import shutil
import subprocess

import pytest

from xray.contract import Entry, parse_contract
from xray.kubernetes import manifests, resource_name, seccomp_profile

BASE = """xray-contract 1
program /usr/bin/Tool_Server

[exec]
/usr/bin/Tool_Server
[write]
/tmp/**
/var/cache/tool/state.db
[net]
{net}
"""


def _contract(net):
    return parse_contract(BASE.format(net=net))


def test_names_are_dns_labels():
    assert resource_name("/usr/bin/Tool_Server") == "tool-server"
    assert resource_name("/x/" + "a" * 80) == "a" * 63


def test_no_network_denies_all_traffic_and_writes_become_volumes():
    text, profile = manifests(_contract("none"), image="example/tool:1")
    assert profile is None and "type: RuntimeDefault" in text
    assert 'readOnlyRootFilesystem: true' in text and 'drop: ["ALL"]' in text and "NET_BIND_SERVICE" not in text
    assert 'mountPath: "/tmp"' in text and 'mountPath: "/var/cache/tool"' in text
    assert "  ingress: []\n  egress: []" in text


def test_low_bind_port_keeps_net_bind_service_and_opens_ingress():
    text, _ = manifests(_contract("bind tcp 80\nconnect tcp 443"))
    assert 'add: ["NET_BIND_SERVICE"]' in text
    assert "protocol: TCP\n          port: 80" in text and "protocol: TCP\n          port: 443" in text


def test_any_network_has_no_policy():
    text, _ = manifests(_contract("any"))
    assert "kind: NetworkPolicy" not in text


def test_syscall_denials_become_a_localhost_profile():
    contract = _contract("none")
    contract.sections["syscalls"] = [Entry("ptrace"), Entry("mount")]
    text, profile = manifests(contract)
    assert 'localhostProfile: "xray/tool-server.json"' in text
    data = json.loads(profile)
    assert data["defaultAction"] == "SCMP_ACT_ALLOW"
    assert data["syscalls"] == [{"names": ["mount", "ptrace"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]
    assert seccomp_profile(_contract("none")) is None


@pytest.mark.parametrize("net", ["none", "bind tcp 80\nconnect tcp 443", "any", "connect udp *"])
def test_manifests_parse_and_validate(tmp_path, net):
    text, _ = manifests(_contract(net), image="example/tool:1")
    yaml = pytest.importorskip("yaml")
    documents = [doc for doc in yaml.safe_load_all(text) if doc]
    assert documents[0]["kind"] == "Pod"
    container = documents[0]["spec"]["containers"][0]
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    validator = shutil.which("kubeconform")
    if validator:
        path = tmp_path / "m.yaml"
        path.write_text(text)
        result = subprocess.run([validator, "-strict", str(path)], capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
