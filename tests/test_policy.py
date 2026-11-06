import json

import pytest

from xray import policy
from xray.driftverbs import run_policy

POLICY = """
# xz never again
deny gain loader-hook
allow gain class:net for ghostty     # it is a terminal with a network feature
deny gain class:net in usr/bin/*
deny gain class:shell in *.so*
deny taint high
deny risk *RPATH*
"""


def gain(field, path, detail="x"):
    return {"field": field, "path": path, "detail": detail}


def test_first_matching_rule_decides():
    rules = policy.parse(POLICY)
    items = (policy.gain_items([gain("class:net", "usr/bin/ghostty")], "ghostty")
             + policy.gain_items([gain("class:net", "usr/bin/curl")], "curl")
             + policy.gain_items([gain("class:net", "usr/lib/libx.so.1")], "x")
             + policy.gain_items([gain("class:shell", "usr/lib/liby.so.2")], "y")
             + policy.gain_items([gain("loader-hook", "usr/lib/liblzma.so.5")], "xz"))

    denied = [(item["package"], rule.line) for item, rule in policy.violations(rules, items)]

    assert denied == [("curl", 5), ("y", 6), ("xz", 3)]


def test_taint_and_risk_items():
    rules = policy.parse(POLICY)
    findings = [{"severity": "high", "file": "/a.sh", "line": 3, "detail": "eval of input"},
                {"severity": "medium", "file": "/b.sh", "line": 1, "detail": "eval of input"}]
    risks = [{"file": "/usr/bin/app", "message": "empty RPATH entry: libraries are searched in the current directory"}]

    denied = policy.violations(rules, policy.taint_items(findings) + policy.risk_items(risks))

    assert [item["path"] for item, _ in denied] == ["/a.sh", "/usr/bin/app"]


@pytest.mark.parametrize("bad", ["block gain x", "deny gains", "deny taint urgent", "deny gain x in", "deny gain x near y"])
def test_bad_rules_name_their_line(bad):
    with pytest.raises(policy.PolicyError, match="line 1"):
        policy.parse(bad)


def test_cli_checks_drift_between_directories(tmp_path, capsys):
    for side, body in (("a", "#!/bin/sh\nls\n"), ("b", "#!/bin/sh\nls\ncurl -s x\n")):
        tool = tmp_path / side / "usr" / "bin" / "tool"
        tool.parent.mkdir(parents=True)
        tool.write_text(body)
        tool.chmod(0o755)
    (tmp_path / "policy").write_text("deny gain class:net in usr/bin/*\n")

    assert run_policy(["check", str(tmp_path / "policy"), "--drift", str(tmp_path / "a"), str(tmp_path / "b"),
                       "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["violations"][0]["rule_line"] == 1
