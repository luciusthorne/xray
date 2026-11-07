"""Analyzer plugins through the xray.analyzers entry point group, end to end."""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

TOYLANG = textwrap.dedent('''
    import re
    from pathlib import Path

    from xray.analyzers import Analyzer
    from xray.model import Edge
    from xray.symbols import Symbol


    class ToyAnalyzer(Analyzer):
        name = "toy"
        kinds = ("toy",)
        language = "Toy"
        comments = ("//", None)

        def claims(self, path):
            return Path(path).suffix == ".toy"

        def symbols(self, path):
            lines = Path(path).read_text().splitlines()
            out = []
            for number, line in enumerate(lines, 1):
                match = re.match(r"fn (\\w+) \\{", line)
                if match:
                    end = next(n for n in range(number, len(lines) + 1) if lines[n - 1].strip() == "}")
                    out.append(Symbol(match[1], "function", str(path), number, None, {"end_line": end}))
            return out

        def edges(self, path):
            out = []
            for line in Path(path).read_text().splitlines():
                match = re.match(r"use (\\w+)", line)
                if match:
                    target = Path(path).parent / f"{match[1]}.toy"
                    out.append(Edge(str(path), str(target) if target.exists() else None, "imports",
                                    "resolved" if target.exists() else "unresolved", name=match[1]))
            return out
''')


def _site(tmp_path, broken=False):
    """A directory on sys.path holding installed-looking packages (dist-info with entry points)."""

    site = tmp_path / "site"
    (site / "toylang").mkdir(parents=True)
    (site / "toylang" / "__init__.py").write_text(TOYLANG)
    info = site / "toylang-0.1.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: toylang\nVersion: 0.1\n")
    (info / "entry_points.txt").write_text("[xray.analyzers]\ntoy = toylang:ToyAnalyzer\n")
    if broken:
        (site / "brokenlang").mkdir()
        (site / "brokenlang" / "__init__.py").write_text("raise RuntimeError('this plugin is broken')\n")
        broken_info = site / "brokenlang-0.1.dist-info"
        broken_info.mkdir()
        (broken_info / "METADATA").write_text("Metadata-Version: 2.1\nName: brokenlang\nVersion: 0.1\n")
        (broken_info / "entry_points.txt").write_text("[xray.analyzers]\nbroken = brokenlang:Analyzer\n")
    return site


def _xray(site, *args, cwd):
    env = dict(os.environ, PYTHONPATH=f"{site}{os.pathsep}{REPO}")
    return subprocess.run([sys.executable, "-m", "xray", *args], capture_output=True, text=True,
                          cwd=cwd, env=env, check=False)


def _project(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "helpers.toy").write_text("fn helper {\n  print(1)\n}\n")
    (work / "main.toy").write_text(
        "use helpers\nfn greet {\n  // helper() in a comment\n  helper()\n}\nfn main {\n  greet()\n}\n")
    return work


def test_a_plugin_language_gets_reports_code_callgraph_and_imports(tmp_path):
    site, work = _site(tmp_path), _project(tmp_path)

    listed = _xray(site, "plugins", cwd=work)
    assert listed.returncode == 0 and "toy" in listed.stdout and "toylang" in listed.stdout

    report = _xray(site, "main.toy", "--report", cwd=work)
    assert report.returncode == 0, report.stderr
    assert "Toy symbols:" in report.stdout and "function greet (line 2)" in report.stdout

    code = _xray(site, "main.toy", "--code", "greet", cwd=work)
    assert "fn greet {" in code.stdout and "helper()" in code.stdout

    graph = _xray(site, "main.toy", "--callgraph", cwd=work)
    assert graph.returncode == 0, graph.stderr
    assert "→ greet" in graph.stdout
    assert "called at line 3" not in graph.stdout  # the comment is not a call

    inspect = _xray(site, "inspect", "./main.toy", cwd=work)
    assert "helpers.toy" in inspect.stdout


def test_a_broken_plugin_is_reported_and_skipped(tmp_path):
    site, work = _site(tmp_path, broken=True), _project(tmp_path)

    listed = _xray(site, "plugins", cwd=work)
    assert listed.returncode == 1
    assert "broken" in listed.stdout and "this plugin is broken" in listed.stdout
    assert "toy" in listed.stdout  # the good plugin still loaded

    report = _xray(site, "main.toy", "--report", cwd=work)
    assert report.returncode == 0 and "function greet" in report.stdout


def test_no_plugins():
    result = subprocess.run([sys.executable, "-m", "xray", "plugins"], capture_output=True, text=True,
                            cwd=REPO, check=False)
    assert result.returncode == 0 and "No plugins installed" in result.stdout
