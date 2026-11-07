"""[syscalls] in capability contracts: generation from evidence, the seccomp filter, enforcement."""

import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from xray import landlock, seccomp
from xray.contract import Contract, ContractError, parse_contract
from xray.observe import parse_capabilities

HEADER = Path("/usr/include/asm/unistd_64.h")


@pytest.mark.skipif(not HEADER.is_file(), reason="kernel headers not installed")
def test_x86_64_numbers_match_the_kernel_headers():
    numbers = {name: int(number) for name, number in re.findall(r"#define __NR_(\w+)\s+(\d+)", HEADER.read_text())}
    assert {name: numbers.get(name) for name in seccomp.X86_64} == seccomp.X86_64


def test_denials_keep_what_the_evidence_needs():
    denied = dict(seccomp.denials(imports={"ptrace", "umount", "printf"}, observed={"bpf"}))
    assert "ptrace" not in denied and "umount2" not in denied and "bpf" not in denied  # import, wrapper, traced run
    assert denied["mount"] == "mounts and namespaces"
    assert len(denied) == len(seccomp.KNOWN) - 3


def test_filter_shape():
    code, count = seccomp.program(["ptrace", "mount"])
    instructions = [struct.unpack_from("<HBBI", code, offset) for offset in range(0, len(code), 8)]
    assert count == len(instructions) == 10
    assert instructions[1][3] == seccomp.AUDIT_ARCH_X86_64
    jumps = [(jt, k) for op, jt, _jf, k in instructions if op == 0x15 and k in (101, 165)]
    assert sorted(k for _, k in jumps) == [101, 165]
    for index, (op, jt, _jf, k) in enumerate(instructions):
        if op == 0x15 and k in (101, 165):
            target = instructions[index + 1 + jt]
            assert target == (0x06, 0, 0, seccomp.SECCOMP_RET_ERRNO | 1)  # EPERM
    assert instructions[-2] == (0x06, 0, 0, seccomp.SECCOMP_RET_ALLOW)


TEXT = """xray-contract 2
program /usr/bin/tool

[exec]
/usr/bin/tool
[syscalls]
deny ptrace        # inferred: debugging other processes
deny mount
"""


def test_syscalls_section_parses_renders_and_validates():
    contract = parse_contract(TEXT)
    assert contract.values("syscalls") == ["ptrace", "mount"]
    rendered = contract.render()
    assert "[syscalls]\ndeny ptrace" in rendered and parse_contract(rendered).values("syscalls") == ["ptrace", "mount"]
    assert rendered.splitlines()[1] == "xray-contract 2"
    plain = Contract(program="/usr/bin/x").render()
    assert "[syscalls]" not in plain and plain.splitlines()[1] == "xray-contract 1"  # older readers still read it
    with pytest.raises(ContractError, match="needs 'xray-contract 2'"):
        parse_contract(TEXT.replace("xray-contract 2", "xray-contract 1"))
    with pytest.raises(ContractError, match="syscalls"):
        parse_contract(TEXT.replace("deny mount", "deny write"))
    with pytest.raises(ContractError, match="syscalls"):
        parse_contract(TEXT.replace("deny mount", "allow mount"))


def test_traced_runs_record_dangerous_calls():
    text = ('100 execve("/usr/bin/tool", ["tool"], 0x0 /* 0 vars */) = 0\n'
            '100 ptrace(PTRACE_TRACEME) = 0\n'
            '100 mount("none", "/x", "tmpfs", 0, NULL) = -1 EPERM (Operation not permitted)\n')
    assert parse_capabilities(text, "/").syscalls == ["ptrace", "mount"]


def test_check_reports_a_denied_call_in_a_traced_run():
    from xray.contractverbs import check_contract
    from xray.evidence import EvidenceGraph
    from xray.observe import Observed

    contract = parse_contract(TEXT)
    graph = EvidenceGraph("/usr/bin/tool")
    graph.add_node("/usr/bin/tool", "elf", "tool")
    result = check_contract(contract, graph, Observed(syscalls=["mount"]))
    assert {"section": "syscalls", "value": "mount", "how": "observed",
            "detail": "the traced run called mount, which the contract denies"} in result["breaches"]


def test_systemd_gets_a_syscall_filter():
    from xray.systemd import directives

    found = dict(directives(parse_contract(TEXT)))
    assert found["SystemCallFilter"] == "~ptrace mount" and found["SystemCallErrorNumber"] == "EPERM"


PROBE = r"""#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    long r = syscall(SYS_ptrace, 0, 0, 0, 0);
    printf("ptrace=%ld errno=%d pid_ok=%d\n", r, r ? errno : 0, syscall(SYS_getpid) > 0);
    return 0;
}
"""


@pytest.mark.skipif(not (shutil.which("cc") and seccomp.supported() and landlock.abi_version() >= 1),
                    reason="needs cc, x86-64 and Landlock")
def test_enforcement_denies_a_call_the_program_never_imports(tmp_path):
    from xray.contractgen import generate
    from xray.enforce import run_enforced

    (tmp_path / "probe.c").write_text(PROBE)
    probe = tmp_path / "probe"
    subprocess.run(["cc", "-O2", "-o", str(probe), str(tmp_path / "probe.c")], check=True)
    assert "ptrace=0 " in subprocess.run([str(probe)], capture_output=True, text=True, check=True).stdout

    contract, _graph = generate(str(probe), packages=False)  # static: no run, so nothing shows ptrace is used
    assert "ptrace" in contract.values("syscalls")
    result = run_enforced(contract, [], capture=True, extra_read=["/"])
    assert "ptrace=-1 errno=1 pid_ok=1" in result.stdout.decode()  # EPERM, and ordinary calls still work
