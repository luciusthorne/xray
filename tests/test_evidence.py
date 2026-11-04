import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import xray.provenance as provenance_module
from xray.entrypoints import import_file_lines
from xray.evidence import BASES, Evidence, add_trace, build_evidence_graph, weakest
from xray.shellscan import command_lines, scan_shell
from xray.trace import TraceResult


def _write(path, text, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.fixture
def bin_dir(tmp_path, monkeypatch):
    folder = tmp_path / "bin"
    _write(folder / "helper", "#!/bin/sh\necho hi\n")
    monkeypatch.setenv("PATH", f"{folder}{os.pathsep}{os.environ.get('PATH', '')}")
    return folder


def _graph(path, **options):
    return build_evidence_graph(str(path), packages=False, **options)


def test_shell_links_carry_line_and_basis(tmp_path, bin_dir):
    lib = _write(tmp_path / "lib.sh", "x=1\n", 0o644)
    script = _write(
        tmp_path / "tool.sh",
        "#!/bin/sh\n# helper in a comment\n. ./lib.sh\nhelper --go\nnot-a-real-command-xyz\n",
    )
    graph = _graph(script)
    root = str(script.resolve())

    runs = graph.links[(root, "command:helper", "runs")]
    assert runs.basis == "inferred"
    assert runs.evidence[0].line == 4
    assert runs.evidence[0].file == root

    resolved = graph.links[("command:helper", str((bin_dir / "helper").resolve()), "resolves_to")]
    assert resolved.basis == "inferred"

    sourced = graph.links[(root, str(lib.resolve()), "sources")]
    assert sourced.evidence[0].line == 3

    assert graph.nodes["command:not-a-real-command-xyz"].attrs["resolved"] is False


def test_shell_that_assigns_path_makes_lookups_guesses(tmp_path, bin_dir):
    script = _write(tmp_path / "tool.sh", "#!/bin/sh\nexport PATH=/opt/x:$PATH\nhelper\n")
    graph = _graph(script)

    link = graph.links[("command:helper", str((bin_dir / "helper").resolve()), "resolves_to")]
    assert link.basis == "guessed"
    assert any("assigns PATH" in entry["message"] for entry in graph.blind_spots)


def test_runtime_built_commands_are_blind_spots_not_commands(tmp_path):
    script = _write(
        tmp_path / "tool.sh",
        '#!/bin/sh\n$(printf "$browser" "$1")\neval "$cmd"\n',
    )

    assert "_" not in scan_shell(script).commands
    graph = _graph(script)
    assert "command:_" not in graph.nodes
    assert any("built at runtime" in entry["message"] for entry in graph.blind_spots)


def test_shebang_is_declared(tmp_path):
    script = _write(tmp_path / "tool.sh", "#!/bin/sh\ntrue\n")
    graph = _graph(script)
    root = str(script.resolve())

    link = next(link for link in graph.outgoing(root) if link.kind == "interpreter")
    assert link.basis == "declared"
    assert link.evidence[0].line == 1


def test_python_imports_have_lines(tmp_path):
    package = tmp_path / "pkg"
    _write(package / "__init__.py", "", 0o644)
    _write(package / "util.py", "X = 1\n", 0o644)
    main = _write(tmp_path / "main.py", "import os\n\nfrom pkg import util\n", 0o644)

    lines = import_file_lines(main)
    assert lines[(package / "util.py").resolve()] == 3

    graph = _graph(main)
    link = graph.links[(str(main.resolve()), str((package / "util.py").resolve()), "imports")]
    assert link.evidence[0].line == 3
    assert link.basis == "inferred"


def test_command_lines_reads_logical_lines(tmp_path):
    script = _write(
        tmp_path / "tool.sh",
        "#!/bin/sh\n# grep in a comment\nfind . \\\n  -exec grep x {} +\ncat <<EOF\nsed\nEOF\n",
    )
    lines = command_lines(script)

    assert lines["find"] == 3
    assert lines["grep"] == 3
    assert "sed" not in lines


@pytest.mark.skipif(shutil.which("readelf") is None, reason="readelf not installed")
def test_real_elf_needs_are_declared_and_resolution_inferred():
    ls = Path(shutil.which("ls")).resolve()
    graph = _graph(ls, max_depth=1)

    needs = [link for link in graph.outgoing(str(ls)) if link.kind == "needs"]
    if not needs:
        pytest.skip("ls is statically linked here")
    assert all(link.basis == "declared" for link in needs)
    libc = graph.find("libc")
    assert libc
    path = graph.paths(libc, max_paths=1)[0]
    assert path[0].kind == "needs"
    assert weakest(link.basis for link in path) in ("declared", "inferred")


def test_weakest_and_evidence_validation():
    assert weakest(["declared", "inferred", "observed"]) == "inferred"
    assert BASES[0] == "observed"
    with pytest.raises(ValueError):
        Evidence("certain", "x", "y")


def test_link_basis_is_strongest_evidence(tmp_path, bin_dir):
    script = _write(tmp_path / "tool.sh", "#!/bin/sh\nhelper\n")
    graph = _graph(script)
    key = (str(script.resolve()), "command:helper", "runs")
    graph.add_link(*key, Evidence("observed", "strace", "seen"))

    assert graph.links[key].basis == "observed"


def test_trace_marks_observed_and_lists_unpredicted(tmp_path, bin_dir):
    script = _write(tmp_path / "tool.sh", "#!/bin/sh\nhelper\n")
    surprise = _write(tmp_path / "surprise", "#!/bin/sh\n")
    graph = _graph(script)
    helper = str((bin_dir / "helper").resolve())

    unpredicted = add_trace(
        graph,
        TraceResult(executed=(helper, str(surprise)), opened=("/usr/share/locale/x.mo",), status=0),
    )

    assert graph.nodes[helper].attrs["observed"] is True
    assert unpredicted == [{"kind": "executed", "path": str(surprise.resolve())}]
    link = graph.links[(graph.root, str(surprise.resolve()), "executed")]
    assert link.basis == "observed"


def test_paths_prefer_the_resolved_file_over_the_name(tmp_path, bin_dir):
    script = _write(tmp_path / "tool.sh", "#!/bin/sh\nhelper\n")
    graph = _graph(script)

    paths = graph.paths(graph.find("helper"))
    assert len(paths) == 1
    assert [link.kind for link in paths[0]] == ["runs", "resolves_to"]


def test_packages_of_parses_pacman(monkeypatch):
    class Done:
        returncode = 1
        stdout = "/usr/bin/ls is owned by coreutils 9.5-1\n"

    monkeypatch.setattr(
        provenance_module.shutil, "which", lambda name: "/usr/bin/pacman" if name == "pacman" else None
    )
    monkeypatch.setattr(provenance_module.subprocess, "run", lambda *args, **kwargs: Done())

    assert provenance_module.packages_of(["/usr/bin/ls", "/tmp/x"]) == {
        "/usr/bin/ls": ("pacman", "coreutils 9.5-1")
    }


def _xray(*args, env=None):
    return subprocess.run(
        [sys.executable, "-m", "xray", *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_cli_why_and_inspect(tmp_path, bin_dir):
    script = _write(tmp_path / "tool.sh", "#!/bin/sh\nhelper\n")
    env = {**os.environ}

    why = _xray("why", str(script), "helper", "--no-packages", env=env)
    assert why.returncode == 0, why.stderr
    assert "as strong as its weakest link: inferred" in why.stdout
    assert f"{script.resolve()}:2" in why.stdout

    data = json.loads(_xray("why", str(script), "helper", "--json", "--no-packages", env=env).stdout)
    assert data["schema_version"] == 1
    assert data["paths"][0]["basis"] == "inferred"

    missing = _xray("why", str(script), "nothing-like-this", "--no-packages", env=env)
    assert missing.returncode == 1
    assert "Not found is not proof of absence" in missing.stdout

    inspect = _xray("inspect", str(script), "--no-packages", env=env)
    assert inspect.returncode == 0, inspect.stderr
    assert "Blind spots" in inspect.stdout
    assert "helper ->" in inspect.stdout

    graph = json.loads(_xray("inspect", str(script), "--json", "--no-packages", env=env).stdout)
    assert graph["root"] == str(script.resolve())
    assert {"nodes", "links", "blind_spots"} <= set(graph)


def test_cli_verb_errors():
    result = _xray("why", "definitely-not-a-command-xyz", "x")
    assert result.returncode != 0
    assert "Not found" in result.stderr

    bad = _xray("inspect", "ls", "--depth", "0")
    assert bad.returncode != 0


def test_packages_of_parses_rpm_in_one_call(monkeypatch):
    calls = []

    class Done:
        returncode = 1
        stdout = "coreutils 9.5-1.fc45.x86_64\nfile /tmp/x is not owned by any package\n"

    def run(args, **kwargs):
        calls.append(args)
        return Done()

    monkeypatch.setattr(
        provenance_module.shutil, "which", lambda name: "/usr/bin/rpm" if name == "rpm" else None
    )
    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    assert provenance_module.packages_of(["/usr/bin/ls", "/tmp/x"]) == {
        "/usr/bin/ls": ("rpm", "coreutils 9.5-1.fc45.x86_64")
    }
    assert len(calls) == 1
