import os
import shutil
import socket
import subprocess
import threading

import pytest

from xray import landlock
from xray.contract import Contract, ContractError, parse_contract
from xray.contractgen import add_observed, from_graph, portable
from xray.contractverbs import check_contract, minimize, run_contract
from xray.enforce import landlock_rules, run_enforced
from xray.evidence import build_evidence_graph
from xray.observe import Observed, parse_capabilities

needs_landlock = pytest.mark.skipif(landlock.abi_version() < 1, reason="Landlock is required")

TEXT = """# comment
xray-contract 1
program /usr/bin/tool
sha256 abc

[exec]
/usr/bin/grep   # inferred: tool:3 runs `grep`
[load]
/usr/lib/libc.so.6
[read]
/etc/tool/*.conf
~/.config/tool/**
[write]
/tmp/**
[net]
connect tcp 443
unix
"""


def test_parse_and_render_round_trip():
    contract = parse_contract(TEXT)

    assert contract.program == "/usr/bin/tool"
    assert contract.sections["exec"][0].comment == "inferred: tool:3 runs `grep`"
    assert parse_contract(contract.render()).render() == contract.render()


@pytest.mark.parametrize("bad, message", [
    ("program x\n", "xray-contract 1"),
    ("xray-contract 1\n[exec]\n/bin/ls\n", "program"),
    ("xray-contract 1\nprogram /a\n[exec]\nrelative/path\n", "absolute"),
    ("xray-contract 1\nprogram /a\n[net]\nconnect tcp lots\n", "net"),
    ("xray-contract 1\nprogram /a\n[bogus]\n", "unknown section"),
    ("xray-contract 1\nprogram /a\n[read]\n/a/**/b\n", "final"),
])
def test_bad_contracts_are_rejected_with_a_line(bad, message):
    with pytest.raises(ContractError, match=message):
        parse_contract(bad)


def test_allows_follows_patterns_implications_and_baseline():
    contract = parse_contract(TEXT)
    home = "/home/u"

    assert contract.allows("exec", "/usr/bin/grep")
    assert contract.allows("read", "/usr/bin/grep")  # exec implies read
    assert not contract.allows("exec", "/usr/bin/sed")
    assert contract.allows("read", "/etc/tool/a.conf")
    assert not contract.allows("read", "/etc/tool/sub/a.conf")
    assert contract.allows("read", "/home/u/.config/tool/x/y", home)
    assert contract.allows("write", "/tmp/a/b")
    assert contract.allows("read", "/tmp/a/b")  # write implies read
    assert not contract.allows("write", "/etc/tool/a.conf")
    assert contract.allows("read", "/etc/ld.so.cache")  # baseline
    assert contract.allows("write", "/dev/null")
    assert contract.net_allows("connect", "tcp", 443)
    assert not contract.net_allows("connect", "tcp", 80)
    assert contract.net_allows("unix")


STRACE = """\
100 execve("/usr/bin/tool", ["tool"], 0x7ffd /* 30 vars */) = 0
100 openat(AT_FDCWD</home/u>, "/etc/tool.conf", O_RDONLY|O_CLOEXEC) = 3</etc/tool.conf>
100 openat(AT_FDCWD</home/u>, "notes.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4</home/u/notes.txt>
100 openat(AT_FDCWD, "/missing", O_RDONLY) = -1 ENOENT (No such file or directory)
100 clone(child_stack=NULL, flags=SIGCHLD) = 101
101 chdir("/srv") = 0
101 openat(AT_FDCWD, "data", O_RDONLY <unfinished ...>
100 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 5<socket:[1]>
101 <... openat resumed>) = 3</srv/data>
100 connect(5<socket:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 EINPROGRESS (Operation now in progress)
100 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 6<socket:[2]>
100 connect(6<socket:[2]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("9.9.9.9")}, 16) = 0
100 connect(7<socket:[3]>, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 110) = 0
101 execve("/usr/bin/helper", ["helper"], 0x1 /* 1 var */) = 0
100 unlinkat(AT_FDCWD, "/tmp/x", 0) = 0
"""


def test_parse_capabilities():
    observed = parse_capabilities(STRACE, "/home/u")

    assert observed.exec == ["/usr/bin/tool", "/usr/bin/helper"]
    assert observed.read == ["/etc/tool.conf", "/srv/data"]
    assert observed.write == ["/home/u/notes.txt", "/tmp/x"]
    assert observed.net == [("connect", "tcp", 443), ("connect", "udp", 53), ("unix", "unix", "/run/dbus/system_bus_socket")]


def test_observed_run_becomes_portable_generalized_entries(tmp_path):
    home = tmp_path / "home"
    config = home / ".config" / "tool"
    config.mkdir(parents=True)
    files = []
    for number in range(6):
        path = config / f"part{number}.conf"
        path.write_text("x")
        files.append(str(path))
    observed = Observed(read=files + ["/etc/ld.so.cache"], write=["/tmp/tool-1234/out"], net=[("connect", "tcp", 443)])

    contract = add_observed(Contract("/usr/bin/tool"), observed, home=str(home))

    assert contract.values("read") == ["~/.config/tool/*"]
    assert contract.values("write") == ["/tmp/**"]
    assert contract.values("net") == ["connect tcp 443"]
    assert portable(str(home / "x"), str(home)) == "~/x"


def script(path, body):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def test_check_reports_a_new_command_with_its_proof_chain(tmp_path):
    tool = script(tmp_path / "tool", "ls\n")
    contract = from_graph(build_evidence_graph(str(tool), packages=False))

    assert check_contract(contract, build_evidence_graph(str(tool), packages=False))["breaches"] == []

    script(tool, "ls\nid -u\n")
    result = check_contract(contract, build_evidence_graph(str(tool), packages=False))
    values = {item["value"] for item in result["breaches"]}

    assert os.path.realpath(shutil.which("id")) in values
    breach = next(item for item in result["breaches"] if item["value"] == os.path.realpath(shutil.which("id")))
    assert breach["chain"][0]["evidence"][0]["line"] == 3


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
def test_check_catches_a_library_a_rebuilt_binary_starts_loading(tmp_path):
    """The xz-style case: the program file changes and now pulls in a new library."""

    (tmp_path / "m.c").write_text("int main(void){return 0;}\n")
    (tmp_path / "f.c").write_text("int f(void){return 1;}\n")
    (tmp_path / "e.c").write_text("int f(void); int main(void){return f();}\n")
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", tmp_path / "libevil.so", tmp_path / "f.c"], check=True)
    app = tmp_path / "app"
    subprocess.run(["gcc", "-o", app, tmp_path / "m.c"], check=True)
    contract = from_graph(build_evidence_graph(str(app), packages=False))
    contract.sha256 = "0" * 64

    subprocess.run(["gcc", "-o", app, tmp_path / "e.c", f"-L{tmp_path}", "-levil", f"-Wl,-rpath,{tmp_path}"], check=True)
    result = check_contract(contract, build_evidence_graph(str(app), packages=False), strict=True)
    values = [item["value"] for item in result["breaches"]]

    assert str((tmp_path / "libevil.so").resolve()) in values
    assert values[0] == str(app)  # the changed file itself, with --strict
    assert result["changed"]


def test_minimize_keeps_only_entries_the_workload_needs():
    contract = parse_contract(TEXT)
    needed = {"/usr/bin/grep", "~/.config/tool/**"}

    def run(trial):
        values = {value for section in trial.sections.values() for value in (entry.value for entry in section)}
        return (0, b"ok") if needed <= values else (1, b"")

    minimal, removed, runs, baseline = minimize(contract, [], everything=True, run=run)

    kept = {entry.value for section in minimal.sections.values() for entry in section}
    assert kept == needed
    assert baseline == (0, b"ok")
    assert all(entry.comment.startswith("required") for section in minimal.sections.values() for entry in section)
    assert len(removed) == 5
    assert runs < 40


def test_landlock_rules_map_sections_to_rights():
    contract = parse_contract(TEXT)
    rules = {path: bits for path, bits in landlock_rules(contract, home="/home/u")["fs"]}

    assert rules["/usr/bin/grep"] & landlock.EXECUTE
    assert not rules["/usr/lib/libc.so.6"] & landlock.EXECUTE
    assert rules["/etc/tool"] == landlock.READ
    assert rules["/home/u/.config/tool"] == landlock.READ
    assert rules["/tmp"] & landlock.MAKE_REG
    net = landlock_rules(contract)["net"]
    assert net["connect"] == [443] and net["handle_connect"]
    assert landlock_rules(contract)["scope_unix"] is False


@needs_landlock
def test_enforced_run_reads_only_what_the_contract_allows(tmp_path):
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("yes\n")
    secret = tmp_path / "secret.txt"
    secret.write_text("no\n")
    tool = script(tmp_path / "tool", 'cat "$1"\n')
    contract = from_graph(build_evidence_graph(str(tool), packages=False))
    contract.add("read", str(allowed))
    contract.add("net", "any")

    ok = run_enforced(contract, [str(allowed)], capture=True)
    denied = run_enforced(contract, [str(secret)], capture=True)

    assert (ok.returncode, ok.stdout) == (0, b"yes\n")
    assert denied.returncode != 0 and b"Permission denied" in denied.stderr


@needs_landlock
def test_enforced_run_cannot_execute_unlisted_programs(tmp_path):
    tool = script(tmp_path / "tool", "echo start\nid -u\n")
    contract = from_graph(build_evidence_graph(str(tool), packages=False))
    contract.remove("exec", os.path.realpath(shutil.which("id")))
    contract.add("net", "any")

    done = run_enforced(contract, [], capture=True)

    assert done.stdout == b"start\n"
    assert b"Permission denied" in done.stderr


@pytest.mark.skipif(landlock.abi_version() < 4 or shutil.which("bash") is None, reason="needs Landlock ABI 4 and bash")
def test_enforced_run_connects_only_to_listed_tcp_ports(tmp_path):
    servers = []
    for _ in range(2):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        servers.append(server)
    def accept(server):
        try:
            server.accept()
        except OSError:
            pass

    for server in servers:
        threading.Thread(target=accept, args=(server,), daemon=True).start()
    allowed, other = (server.getsockname()[1] for server in servers)
    tool = tmp_path / "tool"
    tool.write_text('#!/usr/bin/env bash\nexec 3<>"/dev/tcp/127.0.0.1/$1" && echo connected\n')
    tool.chmod(0o755)
    contract = from_graph(build_evidence_graph(str(tool), packages=False))
    contract.add("net", f"connect tcp {allowed}")

    assert run_enforced(contract, [str(allowed)], capture=True).stdout == b"connected\n"
    assert run_enforced(contract, [str(other)], capture=True).stdout == b""
    for server in servers:
        server.close()


@needs_landlock
@pytest.mark.skipif(shutil.which("bwrap") is None, reason="needs bubblewrap")
def test_net_none_runs_in_a_private_network_namespace(tmp_path):
    tool = script(tmp_path / "tool", "cat /proc/net/dev\n")
    contract = from_graph(build_evidence_graph(str(tool), packages=False))

    done = run_enforced(contract, [], capture=True)

    if done.returncode != 0 and b"bwrap" in done.stderr:
        pytest.skip("unprivileged user namespaces are not available here")
    interfaces = [line.split(":")[0].strip() for line in done.stdout.decode().splitlines()[2:]]
    assert interfaces == ["lo"]


def test_cli_generate_then_check(tmp_path, capsys):
    tool = script(tmp_path / "tool", "ls\n")
    output = tmp_path / "tool.contract"

    assert run_contract(["generate", str(tool), "--no-packages", "-o", str(output)]) == 0
    assert run_contract(["check", str(output)]) == 0
    script(tool, "ls\nid\n")
    assert run_contract(["check", str(output)]) == 1
    assert "BREACH" in capsys.readouterr().out


@pytest.mark.skipif(not (os.environ.get("XRAY_STRACE") or shutil.which("strace")), reason="needs strace")
def test_generate_with_a_traced_run_records_reads_and_writes(tmp_path):
    from xray.contractgen import generate

    config = tmp_path / "tool.conf"
    config.write_text("x\n")
    out = tmp_path / "out.txt"
    tool = script(tmp_path / "tool", f'cat {config} > {out}\n')

    contract, _ = generate(str(tool), [], packages=False)

    assert str(config) in contract.values("read") or portable(str(config)) in contract.values("read")
    assert portable(str(out)) in contract.values("write") or any(v.endswith("/**") for v in contract.values("write"))
    assert os.path.realpath(shutil.which("cat")) in contract.values("exec")
    assert contract.workload == "tool"
