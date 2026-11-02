import http.client
import io
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

from xray import cli
from xray.calls import calls_lines
from xray.codeview import code_lines
from xray.command_analyzers import PerlAnalyzer, ShellAnalyzer
from xray.disasm import DisasmResult, disasm_result, parse_calls
from xray.elfscan import ElfScan
from xray.errors import AnalysisError
from xray.export import export_data
from xray.graphjson import graph_data
from xray.html import render_html
from xray.javascript_analyzer import JavaScriptAnalyzer
from xray.minidebug import (
    parse_function_table,
    parse_functions,
    read_function_table,
    read_minidebuginfo,
)
from xray.model import Edge, edge_data
from xray.provenance import package_manager, package_of
from xray.python_analyzer import PythonAnalyzer
from xray.report import report_lines
from xray.rizinview import INSTALL_HINT, function_lines
from xray.ruby_analyzer import RubyAnalyzer
from xray.serve import _local_host, make_server
from xray.sourcelookup import (
    cached_source_files,
    file_lines,
    source_files,
    source_lines,
)
from xray.treesitter_analyzers import (
    CAnalyzer,
    LuaAnalyzer,
    TypeScriptAnalyzer,
    _json_payload,
    _read_snapshot,
    parser_available,
)


class AuditFixTests(unittest.TestCase):
    def test_minidebug_parsers_ignore_undefined_and_deduplicate_symbols(self):
        readelf = (
            "  1: 0000000000001000    11 FUNC    GLOBAL DEFAULT   12 helper\n"
            "  2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND external\n"
            "  3: 0000000000001000    11 FUNC    GLOBAL DEFAULT   12 helper@@LIB_1\n"
            "  4: 0000000000002000     4 OBJECT  GLOBAL DEFAULT   13 data\n"
        )

        self.assertEqual(parse_functions(readelf), ("helper",))
        self.assertEqual(parse_function_table(readelf), ((0x1000, 11, "helper"),))

    def test_disasm_parser_classifies_direct_and_unresolved_calls(self):
        objdump = (
            "    1001: call 1020 <helper>\n"
            "    1002: call 1021 <helper+0x1>\n"
            "    1003: call 9999 <unknown>\n"
            "    1004: call *%rax\n"
            "    1005: call 3000 <puts@plt>\n"
            "    2000: call 1020 <helper>\n"
        )
        table = ((0x1000, 0x10, "main"), (0x1020, 4, "helper"))

        result = parse_calls(objdump, table)

        self.assertEqual(
            result,
            DisasmResult(
                {"main": ("helper", "puts@plt")},
                indirect=1,
                offset=1,
                unresolved=1,
                unattributed=1,
            ),
        )

    def test_elf_calls_do_not_report_unresolved_libraries_as_resolved(self):
        scan = ElfScan(needed=("libmissing-xray.so",))
        with tempfile.NamedTemporaryFile() as target:
            Path(target.name).write_bytes(b"\x7fELF" + bytes(60))
            with (
                patch("xray.calls.scan_elf", return_value=scan),
                patch("xray.command_analyzers.scan_elf", return_value=scan),
                patch("xray.command_analyzers.ldconfig_cache", return_value={}),
                patch("xray.command_analyzers.find_library", return_value=None),
            ):
                lines = calls_lines(target.name)

        self.assertIn("- libmissing-xray.so -> not found", lines)

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("gcc", "objcopy", "readelf", "strip", "xz")),
        "GNU ELF tools are required for the .gnu_debugdata integration test",
    )
    def test_minidebug_reads_functions_from_real_gnu_debugdata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "fixture.c"
            binary = root / "fixture"
            debug = root / "fixture.debug"
            compressed = root / "fixture.mini"
            source.write_text(
                "int helper(void) { return 4; }\n"
                "int main(void) { return helper(); }\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["gcc", "-g", "-O0", "-o", str(binary), str(source)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["objcopy", "--only-keep-debug", str(binary), str(debug)],
                check=True,
                capture_output=True,
            )
            payload = subprocess.run(
                ["xz", "-c", str(debug)], check=True, capture_output=True
            ).stdout
            compressed.write_bytes(payload)
            subprocess.run(
                ["strip", "--strip-debug", str(binary)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["objcopy", "--add-section", f".gnu_debugdata={compressed}", str(binary)],
                check=True,
                capture_output=True,
            )

            names = read_minidebuginfo(binary)
            table = read_function_table(binary)

        self.assertIn("helper", names)
        self.assertIn("main", names)
        self.assertIn("helper", {entry[2] for entry in table})
        self.assertIn("main", {entry[2] for entry in table})

    @unittest.skipUnless(
        all(
            shutil.which(tool)
            for tool in ("gcc", "objcopy", "objdump", "readelf", "strip", "xz")
        ),
        "GNU ELF toolchain is required for the objdump integration test",
    )
    def test_disasm_attributes_real_objdump_calls_using_gnu_debugdata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "calls.c"
            binary = root / "calls"
            debug = root / "calls.debug"
            compressed = root / "calls.mini"
            source.write_text(
                "__attribute__((noinline)) int helper(int value) { return value + 1; }\n"
                "int main(void) { return helper(4); }\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["gcc", "-g", "-O0", "-fno-inline", "-o", str(binary), str(source)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["objcopy", "--only-keep-debug", str(binary), str(debug)],
                check=True,
                capture_output=True,
            )
            compressed.write_bytes(
                subprocess.run(
                    ["xz", "-c", str(debug)], check=True, capture_output=True
                ).stdout
            )
            subprocess.run(
                ["strip", "--strip-debug", str(binary)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["objcopy", "--add-section", f".gnu_debugdata={compressed}", str(binary)],
                check=True,
                capture_output=True,
            )

            result = disasm_result(binary)

        self.assertIsNotNone(result)
        self.assertIn("helper", result.calls["main"])

    def test_rizin_disassembly_uses_symbol_address_not_name(self):
        result = subprocess.CompletedProcess(
            [], 0, "0x401020  safe_func\n  401020: ret\n", ""
        )
        with (
            tempfile.NamedTemporaryFile() as target,
            patch("xray.rizinview.command_kind", return_value="elf"),
            patch(
                "xray.rizinview.read_function_table",
                return_value=[(0x401020, 1, "safe_func")],
            ),
            patch("xray.rizinview.subprocess.run", return_value=result) as run,
        ):
            lines = function_lines(target.name, "safe_func")

        self.assertEqual(lines, ["0x401020  safe_func", "  401020: ret"])
        command = run.call_args.args[0]
        self.assertEqual(command[0], "rizin")
        self.assertEqual(command[-2], "aa; s 0x401020; af; pdf")
        self.assertNotIn("safe_func", command[-2])

    def test_rizin_disassembly_does_not_invoke_unknown_function_name(self):
        with (
            tempfile.NamedTemporaryFile() as target,
            patch("xray.rizinview.command_kind", return_value="elf"),
            patch(
                "xray.rizinview.read_function_table",
                return_value=[(0x401020, 1, "safe_func")],
            ),
            patch("xray.rizinview.subprocess.run") as run,
        ):
            lines = function_lines(target.name, "safe_func; q")

        self.assertIn("Unknown function: safe_func; q", lines[0])
        run.assert_not_called()

    def test_rizin_disassembly_reports_missing_executable_hint(self):
        with (
            tempfile.NamedTemporaryFile() as target,
            patch("xray.rizinview.command_kind", return_value="elf"),
            patch(
                "xray.rizinview.read_function_table",
                return_value=[(0x401020, 1, "safe_func")],
            ),
            patch("xray.rizinview.subprocess.run", side_effect=FileNotFoundError),
        ):
            lines = function_lines(target.name, "safe_func")

        self.assertEqual(lines, [INSTALL_HINT])

    def test_html_graph_data_cannot_close_its_script_element(self):
        hostile = "</script><script>alert(1)</script>"
        data = {
            "root": f"/tmp/{hostile}",
            "nodes": [{"id": hostile, "kind": "python"}],
            "edges": [],
            "metadata": {"truncated": False},
        }

        page = render_html(data)

        self.assertNotIn(hostile, page)
        self.assertIn("\\u003c/script>", page)

    def test_code_view_shows_named_python_function_with_decorator(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.py"
            target.write_text(
                "def marker(fn):\n"
                "    return fn\n\n"
                "@marker\n"
                "async def chosen():\n"
                "    return 7\n\n"
                "def after():\n"
                "    return 8\n",
                encoding="utf-8",
            )

            lines = code_lines(target, "chosen")

        self.assertEqual(lines[0], "    4  @marker")
        self.assertIn("    5  async def chosen():", lines)
        self.assertIn("    6      return 7", lines)
        self.assertFalse(any("def after" in line for line in lines))

    def test_code_view_supports_shell_functions_and_perl_subroutines(self):
        with tempfile.TemporaryDirectory() as directory:
            shell = Path(directory) / "sample.sh"
            shell.write_text(
                "#!/bin/sh\n"
                "before() { echo before; }\n"
                "target() { echo target; }\n",
                encoding="utf-8",
            )
            perl = Path(directory) / "sample.pl"
            perl.write_text(
                "sub before { return 1; }\n"
                "sub target { return 2; }\n",
                encoding="utf-8",
            )

            shell_lines = code_lines(shell, "target")
            perl_lines = code_lines(perl, "target")

        self.assertEqual(shell_lines[0], "    3  target() { echo target; }")
        self.assertEqual(perl_lines[0], "    2  sub target { return 2; }")

    def test_code_view_supports_available_parser_backed_languages(self):
        cases = []
        if shutil.which("node"):
            cases.append(("sample.js", "function target() { return 1; }\n"))
        if shutil.which("ruby"):
            cases.append(("sample.rb", "def target\n  1\nend\n"))
        for language, case in (
            ("lua", ("sample.lua", "function target() return 1 end\n")),
            ("typescript", ("sample.ts", "function target(): number { return 1; }\n")),
            ("c", ("sample.c", "int target(void) { return 1; }\n")),
        ):
            if parser_available(language):
                cases.append(case)

        with tempfile.TemporaryDirectory() as directory:
            for filename, source in cases:
                with self.subTest(language=Path(filename).suffix):
                    target = Path(directory) / filename
                    target.write_text(source, encoding="utf-8")
                    lines = code_lines(target, "target")
                    self.assertIn("target", lines[0])

    def test_code_view_resolves_qualified_python_method_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.py"
            marker = Path(directory) / "executed"
            target.write_text(
                f"from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('ran')\n"
                "class Worker:\n"
                "    def run(self):\n"
                "        return 'ready'\n",
                encoding="utf-8",
            )

            lines = code_lines(target, "Worker.run")
            class_lines = code_lines(target, "Worker")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(
                    sys, "argv", ["xray", str(target), "--code", "Worker.run"]
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = cli.main()

        self.assertIn("    4      def run(self):", lines)
        self.assertEqual(class_lines[0], "    3  class Worker:")
        self.assertIn("    4      def run(self):", class_lines)
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn("def run(self):", stdout.getvalue())
        self.assertFalse(marker.exists())

    def test_source_viewer_requests_loopback_only(self):
        data = {
            "root": "/tmp/xray-command",
            "nodes": [],
            "edges": [],
            "metadata": {"truncated": False},
        }
        sentinel = object()

        with patch("xray.serve.ThreadingHTTPServer", return_value=sentinel) as server:
            result = make_server(data["root"], data)

        self.assertIs(result, sentinel)
        self.assertEqual(server.call_args.args[0], ("127.0.0.1", 0))

    def test_source_viewer_rejects_nonlocal_host_headers(self):
        for host in ("127.0.0.1", "127.0.0.1:8080", "localhost", "localhost:8080"):
            with self.subTest(host=host):
                self.assertTrue(_local_host(host))

        for host in (
            None,
            "example.test",
            "127.0.0.1.example.test:8080",
            "localhost.evil:8080",
            "localhost:not-a-port",
        ):
            with self.subTest(host=host):
                self.assertFalse(_local_host(host))

    def test_source_viewer_live_loopback_routes_enforce_host_and_file_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root.py"
            root.write_text("def main():\n    return 7\n", encoding="utf-8")
            outside = Path(directory) / "outside.py"
            outside.write_text("secret = True\n", encoding="utf-8")
            data = {
                "root": str(root),
                "nodes": [{"id": str(root), "kind": "python"}],
                "edges": [],
                "metadata": {"truncated": False},
            }
            server = make_server(root, data)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def get(path, host=None):
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=3
                )
                headers = {} if host is None else {"Host": host}
                try:
                    connection.request("GET", path, headers=headers)
                    response = connection.getresponse()
                    return response.status, response.getheader("Content-Type"), response.read()
                finally:
                    connection.close()

            try:
                status, content_type, body = get("/")
                self.assertEqual(status, 200)
                self.assertIn("text/html", content_type)
                self.assertIn(b"<!doctype html>", body.lower())

                query = urlencode({"path": str(root)})
                status, _content_type, body = get(f"/api/text?{query}")
                self.assertEqual(status, 200)
                self.assertIn(b"def main", body)

                query = urlencode({"path": str(outside)})
                self.assertEqual(get(f"/api/text?{query}")[0], 404)
                self.assertEqual(get("/", host="example.invalid")[0], 403)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

    def test_source_viewer_live_binary_routes_respect_function_and_file_allowlists(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_bytes(b"fixture binary")
            source_root = Path(directory) / "source"
            source_root.mkdir()
            data = {
                "root": str(binary),
                "nodes": [{"id": str(binary), "kind": "elf"}],
                "edges": [],
                "metadata": {"truncated": False},
            }

            with (
                patch("xray.serve.command_kind", return_value="elf"),
                patch("xray.serve.read_function_table", return_value=[(256, 4, "main")]),
                patch(
                    "xray.serve.source_files",
                    return_value=({"fixture.c": ["main"]}, source_root),
                ),
                patch(
                    "xray.serve.file_lines",
                    return_value=["    1  int main(void) { return 0; }"],
                ),
                patch(
                    "xray.serve.source_lines",
                    return_value=["fixture.c:1", "int main(void) { return 0; }"],
                ),
                patch(
                    "xray.serve.function_lines",
                    return_value=["0x100  main"],
                ),
            ):
                server = make_server(binary, data)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

                def get(path):
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", server.server_address[1], timeout=3
                    )
                    try:
                        connection.request("GET", path)
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()

                try:
                    status, body = get("/api/files")
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body), {"files": {"fixture.c": 1}})

                    query = urlencode({"path": "fixture.c"})
                    status, body = get(f"/api/file?{query}")
                    self.assertEqual(status, 200)
                    self.assertIn(b"int main", body)

                    query = urlencode({"name": "main"})
                    self.assertEqual(get(f"/api/source?{query}")[0], 200)
                    self.assertEqual(get(f"/api/disasm?{query}")[0], 200)

                    query = urlencode({"name": "unknown"})
                    self.assertEqual(get(f"/api/source?{query}")[0], 404)
                    query = urlencode({"path": "outside.c"})
                    self.assertEqual(get(f"/api/file?{query}")[0], 404)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)

    def test_source_file_reader_rejects_traversal_and_escaping_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "source"
            root.mkdir()
            safe = root / "safe.c"
            safe.write_text("int safe;\n", encoding="utf-8")
            long_file = root / "long.c"
            long_file.write_text(
                "\n".join(f"int line_{number};" for number in range(405)),
                encoding="utf-8",
            )
            outside = parent / "private.c"
            outside.write_text("int private;\n", encoding="utf-8")
            (root / "escape.c").symlink_to(outside)

            self.assertEqual(file_lines(root, "safe.c"), ["    1  int safe;"])
            shown = file_lines(root, "long.c")
            self.assertEqual(len(shown), 401)
            self.assertEqual(shown[-1], "... and 5 more lines")
            self.assertEqual(file_lines(root, "../private.c"), ["Not a source file"])
            self.assertEqual(file_lines(root, "escape.c"), ["Not a source file"])

    def test_package_of_resolves_pacman_owner_and_version(self):
        owner = subprocess.CompletedProcess([], 0, "bash\n", "")
        version = subprocess.CompletedProcess([], 0, "bash 5.3.20-1\n", "")
        with tempfile.NamedTemporaryFile() as target, \
                patch("xray.provenance.shutil.which", side_effect=lambda name: "/usr/bin/pacman" if name == "pacman" else None), \
                patch("xray.provenance.subprocess.run", side_effect=[owner, version]):
            self.assertEqual(package_of(target.name), "bash 5.3.20-1")

    def test_package_manager_prefers_rpm_when_rpm_owns_file(self):
        with patch("xray.provenance._rpm_package", return_value="bash-5.3-1.x86_64"), \
                patch("xray.provenance._pacman_package") as pacman:
            self.assertEqual(package_manager("/usr/bin/bash"), "rpm")
        pacman.assert_not_called()

    def test_package_manager_reports_pacman_owner(self):
        with patch("xray.provenance._rpm_package", return_value=None), \
                patch("xray.provenance._pacman_package", return_value="bash 5.3.20-1"):
            self.assertEqual(package_manager("/usr/bin/bash"), "pacman")

    def test_package_of_resolves_rpm_owner_and_release(self):
        result = subprocess.CompletedProcess([], 0, "bash-5.3.20-1.x86_64\n", "")
        with (
            tempfile.NamedTemporaryFile() as target,
            patch(
                "xray.provenance.shutil.which",
                side_effect=lambda name: "/usr/bin/rpm" if name == "rpm" else None,
            ),
            patch("xray.provenance.subprocess.run", return_value=result),
            patch("xray.provenance._pacman_package") as pacman,
        ):
            self.assertEqual(package_of(target.name), "bash-5.3.20-1.x86_64")

        pacman.assert_not_called()

    def test_package_of_falls_back_to_pacman_when_rpm_does_not_own_file(self):
        rpm_miss = subprocess.CompletedProcess([], 1, "", "not owned")
        owner = subprocess.CompletedProcess([], 0, "bash\n", "")
        version = subprocess.CompletedProcess([], 0, "bash 5.3.20-1\n", "")

        with (
            tempfile.NamedTemporaryFile() as target,
            patch(
                "xray.provenance.shutil.which",
                side_effect=lambda name: {
                    "rpm": "/usr/bin/rpm",
                    "pacman": "/usr/bin/pacman",
                }.get(name),
            ),
            patch(
                "xray.provenance.subprocess.run",
                side_effect=[rpm_miss, owner, version],
            ),
        ):
            self.assertEqual(package_of(target.name), "bash 5.3.20-1")

    def test_elf_report_explains_pacman_source_fallback(self):
        with tempfile.NamedTemporaryFile() as target, \
                patch("xray.report.command_kind", return_value="elf"), \
                patch("xray.report.package_of", return_value="bash 5.3.20-1"), \
                patch("xray.report.package_manager", return_value="pacman"), \
                patch("xray.report.overview_lines", return_value=[]), \
                patch("xray.report.cached_source_files", return_value=None), \
                patch("xray.debuginfod.configured", return_value=False):
            lines = report_lines(target.name)

        self.assertTrue(any("Pacman-owned source is not fetched automatically" in line for line in lines))
        self.assertTrue(any("objdump disassembly" in line for line in lines))

    def test_elf_report_mentions_configured_debuginfod(self):
        with tempfile.NamedTemporaryFile() as target, \
                patch("xray.report.command_kind", return_value="elf"), \
                patch("xray.report.package_of", return_value="coreutils 9.12-2"), \
                patch("xray.report.package_manager", return_value="pacman"), \
                patch("xray.report.overview_lines", return_value=[]), \
                patch("xray.report.cached_source_files", return_value=None), \
                patch("xray.debuginfod.configured", return_value=True):
            lines = report_lines(target.name)

        self.assertTrue(any("configured debuginfod" in line for line in lines))

    def test_source_lookup_explains_unsupported_package_manager(self):
        with patch("xray.sourcelookup.command_kind", return_value="elf"), \
                patch("xray.sourcelookup.read_function_table", return_value=[("FUNC", 1, "main", 1)]), \
                patch("xray.sourcelookup._query", return_value=None), \
                patch("xray.sourcelookup.package_of", return_value="bash 5.3.20-1"):
            files, message = source_files("/usr/bin/bash")

        self.assertIsNone(files)
        self.assertIn("Package bash 5.3.20-1 owns this file", message)
        self.assertIn("supports RPM packages", message)

    def test_source_function_lookup_names_pacman_owner(self):
        with (
            tempfile.NamedTemporaryFile() as target,
            patch("xray.sourcelookup.command_kind", return_value="elf"),
            patch("xray.sourcelookup.read_function_table", return_value=[]),
            patch("xray.sourcelookup._query", return_value=None),
            patch("xray.sourcelookup.package_of", return_value="bash 5.3.20-1"),
        ):
            lines = source_lines(target.name, "main")

        self.assertIn("Package bash 5.3.20-1 owns this file", lines[0])
        self.assertIn("supports RPM packages", lines[0])

    def test_source_function_lookup_identifies_unowned_file(self):
        with (
            tempfile.NamedTemporaryFile() as target,
            patch("xray.sourcelookup.command_kind", return_value="elf"),
            patch("xray.sourcelookup.read_function_table", return_value=[]),
            patch("xray.sourcelookup._query", return_value=None),
            patch("xray.sourcelookup.package_of", return_value=None),
        ):
            lines = source_lines(target.name, "main")

        self.assertEqual(
            lines,
            ["No installed package owns this file, so there is no source package"],
        )

    def test_source_cli_shows_pacman_owner_when_fetch_is_unsupported(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "binary"
            target.write_bytes(b"fixture")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch("xray.cli.command_kind", return_value="elf"),
                patch("xray.sourcelookup.command_kind", return_value="elf"),
                patch("xray.sourcelookup.read_function_table", return_value=[]),
                patch("xray.sourcelookup._query", return_value=None),
                patch(
                    "xray.sourcelookup.package_of",
                    return_value="bash 5.3.20-1",
                ),
                patch.object(
                    sys, "argv", ["xray", str(target), "--source", "main"]
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = cli.main()

        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn("Package bash 5.3.20-1 owns this file", stdout.getvalue())
        self.assertIn("supports RPM packages", stdout.getvalue())

    def test_report_text_and_markdown_sections(self):
        with tempfile.TemporaryDirectory(prefix="xray report ") as directory:
            target = Path(directory) / "script.sh"
            target.write_text("#!/bin/sh\necho hello\n", encoding="utf-8")
            with patch("xray.report.package_of", return_value=None), \
                    patch("xray.report.overview_lines", return_value=["Commands: 1"]), \
                    patch("xray.report.cached_source_files", return_value=None):
                text = "\n".join(report_lines(target))
                markdown = "\n".join(report_lines(target, markdown=True))

        self.assertIn("Identity\n────────", text)
        self.assertIn("Overview\n────────", text)
        self.assertIn("Source files\n────────", text)
        self.assertIn("## Identity", markdown)
        self.assertIn("## Overview", markdown)
        self.assertIn("## Source files", markdown)
        self.assertIn("```\nCommands: 1\n```", markdown)
        self.assertIn("- Path:", markdown)

    def test_markdown_report_escapes_backticks_in_paths_and_commands(self):
        with tempfile.TemporaryDirectory(prefix="xray ` report ") as directory:
            target = Path(directory) / "tool ` one.sh"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            with patch("xray.report.package_of", return_value=None), \
                    patch("xray.report.overview_lines", return_value=[]), \
                    patch("xray.report.cached_source_files", return_value=None):
                markdown = "\n".join(report_lines(target, markdown=True))

        self.assertIn(f"- Path: ``{target}``", markdown)
        self.assertIn("display it with ``xray '", markdown)
        self.assertIn("--code``", markdown)

    def test_report_and_inspect_cli_modes_render_text_and_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "script.sh"
            target.write_text("#!/bin/sh\necho hello\n", encoding="utf-8")

            def invoke(arguments):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    patch.object(sys, "argv", ["xray", str(target), *arguments]),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    status = cli.main()
                self.assertEqual(status, 0, stderr.getvalue())
                return stdout.getvalue()

            report = invoke(["--report"])
            inspect = invoke(["--inspect"])
            report_md = invoke(["--report", "--md"])
            inspect_md = invoke(["--inspect", "--md"])

        self.assertIn("Report of script.sh", report)
        self.assertIn("Inspection of script.sh", inspect)
        for output in (report, inspect):
            self.assertIn("Identity", output)
            self.assertIn("Source files", output)
        self.assertIn("# Report:", report_md)
        self.assertIn("# Inspection:", inspect_md)
        for output in (report_md, inspect_md):
            self.assertIn("## Identity", output)
            self.assertIn("## Source files", output)

    def test_cached_elf_sources_are_listed_when_marked_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            package_root = cache / "bash-src"
            package_root.mkdir()
            (package_root / ".done").touch()
            with patch("xray.sourcelookup.command_kind", return_value="elf"), \
                    patch("xray.sourcelookup._query", return_value=("bash", "bash-src")), \
                    patch("xray.sourcelookup.cache_root", return_value=cache), \
                    patch("xray.sourcelookup.read_function_table", return_value=[("addr", "size", "main")]), \
                    patch("xray.sourcelookup.index_functions", return_value={"main": ("src/bash.c", 10)}):
                files = cached_source_files("/usr/bin/bash")

        self.assertEqual(files, {"src/bash.c": ["main"]})

    def test_cached_elf_sources_are_none_until_cache_marker_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "bash-src").mkdir()
            with patch("xray.sourcelookup.command_kind", return_value="elf"), \
                    patch("xray.sourcelookup._query", return_value=("bash", "bash-src")), \
                    patch("xray.sourcelookup.cache_root", return_value=cache), \
                    patch("xray.sourcelookup.read_function_table") as read_table:
                files = cached_source_files("/usr/bin/bash")

        self.assertIsNone(files)
        read_table.assert_not_called()

    def test_cached_source_listing_does_not_handle_non_elf(self):
        with patch("xray.sourcelookup.command_kind", return_value="shell"), \
                patch("xray.sourcelookup._query") as query:
            files = cached_source_files("/bin/example.sh")

        self.assertIsNone(files)
        query.assert_not_called()

    def test_static_analyzers_read_but_do_not_execute_targets(self):
        with tempfile.TemporaryDirectory(prefix="xray static ") as directory:
            root = Path(directory)
            marker = root / "executed"
            marker_text = str(marker).replace("\\", "\\\\").replace('"', '\\"')
            cases = [
                ("python", "target.py", f'from pathlib import Path\nPath("{marker_text}").write_text("ran")\ndef target(): pass\n', PythonAnalyzer().symbols),
                ("shell", "target.sh", f'#!/bin/sh\ntouch "{marker_text}"\ntarget() {{ :; }}\n', ShellAnalyzer().edges),
                ("perl", "target.pl", f'#!/usr/bin/perl\nsystem("touch {marker_text}");\nsub target {{ 1 }}\n', PerlAnalyzer().edges),
            ]
            if shutil.which("node"):
                cases.append(("javascript", "target.js", f'require("node:fs").writeFileSync("{marker_text}", "ran");\nfunction target() {{}}\n', JavaScriptAnalyzer().symbols))
            if shutil.which("ruby"):
                cases.append(("ruby", "target.rb", f'File.write("{marker_text}", "ran")\ndef target; end\n', RubyAnalyzer().symbols))
            parser_cases = [
                ("lua", "target.lua", f'os.execute("touch {marker_text}")\nfunction target() end\n', LuaAnalyzer().symbols),
                ("typescript", "target.ts", f'import fs from "node:fs"; fs.writeFileSync("{marker_text}", "ran"); class Store {{ target() {{}} }}\n', TypeScriptAnalyzer().symbols),
                ("c", "target.c", f'void target(void) __attribute__((constructor));\nvoid target(void) {{ system("touch {marker_text}"); }}\n', CAnalyzer().symbols),
            ]
            cases.extend(case for case in parser_cases if parser_available(case[0]))

            self.assertGreaterEqual(len(cases), 3)
            for name, filename, source, analyze in cases:
                with self.subTest(analyzer=name):
                    marker.unlink(missing_ok=True)
                    target = root / filename
                    target.write_text(source, encoding="utf-8")
                    analyze(target)
                    self.assertFalse(marker.exists(), f"{name} analyzer executed its target")

    def test_single_file_json_has_stable_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.py"
            target.write_text("import json\n\ndef greet():\n    return 'hello'\n", encoding="utf-8")
            data = export_data(target)

        self.assertEqual(
            set(data),
            {"schema_version", "file", "kind", "language", "analyzer", "symbols", "edges", "notes", "metadata"},
        )
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["kind"], "python")
        self.assertEqual(data["language"], "Python")
        self.assertEqual(data["analyzer"], "python")
        self.assertIn("greet", [item["name"] for item in data["symbols"]])
        self.assertEqual(set(data["symbols"][0]), {"name", "qualified_name", "kind", "file", "line", "parent", "metadata"})
        self.assertIn("filesystem", data["metadata"])
        self.assertIn("package", data["metadata"])
        json_edge = next(edge for edge in data["edges"] if edge["name"] == "json")
        self.assertEqual(json_edge["status"], "external")
        self.assertIsNone(json_edge["target"])

    def test_graph_json_preserves_unresolved_edge_name(self):
        missing = "xray_missing_command_9d5d5"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.sh"
            target.write_text(f"#!/bin/sh\n{missing}\n", encoding="utf-8")
            with patch("xray.command_analyzers.locate", return_value=None):
                data = graph_data(target, max_depth=5, max_files=10)

        edge = next(edge for edge in data["edges"] if edge["name"] == missing)
        self.assertEqual(edge["status"], "unresolved")
        self.assertIsNone(edge["target"])

    def test_graph_json_schema_and_depth_truncation_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.sh"
            target.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            with patch("xray.graphjson._children", return_value=[
                ("runs", Path(directory) / "child", "child", "resolved", "script")
            ]):
                data = graph_data(target, max_depth=0, max_files=1)

        self.assertEqual(set(data), {"root", "nodes", "edges", "metadata"})
        self.assertEqual(set(data["metadata"]), {"schema_version", "xray_version", "max_depth", "max_files", "max_functions", "truncated"})
        self.assertEqual(data["metadata"]["schema_version"], 1)
        self.assertEqual(data["metadata"]["max_depth"], 0)
        self.assertEqual(data["metadata"]["max_files"], 1)
        self.assertEqual(data["metadata"]["max_functions"], 300)
        self.assertTrue(data["metadata"]["truncated"])
        self.assertEqual(len(data["nodes"]), 1)

    def test_graph_json_function_cap_is_reported_and_marks_truncation(self):
        with tempfile.NamedTemporaryFile() as target:
            found = SimpleNamespace(calls={"main": ["helper"]})
            with (
                patch("xray.graphjson.command_kind", return_value="elf"),
                patch("xray.graphjson._children", return_value=[]),
                patch("xray.graphjson.disasm_result", return_value=found),
            ):
                data = graph_data(
                    target.name,
                    functions=True,
                    max_functions=1,
                )

        self.assertEqual(data["metadata"]["max_functions"], 1)
        self.assertTrue(data["metadata"]["truncated"])
        function_nodes = [n["id"] for n in data["nodes"] if n["kind"] == "function"]
        self.assertEqual(len(function_nodes), 1)
        self.assertTrue(function_nodes[0].endswith(":main"))

    def test_graph_json_file_cap_sets_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.sh"
            target.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            with patch("xray.graphjson._children", return_value=[
                ("runs", Path(directory) / "child", "child", "resolved", "script")
            ]):
                data = graph_data(target, max_depth=5, max_files=1)

        self.assertTrue(data["metadata"]["truncated"])
        self.assertEqual(len(data["nodes"]), 1)
        self.assertEqual(data["edges"], [])

    def test_treesitter_json_ignores_trailing_nvim_log_line(self):
        response = {"symbols": [], "imports": []}
        data = _json_payload([
            '{"symbols":[],"imports":[]}',
            'log: "/home/user/.local/state/nvim/nvim.log" not accessible',
        ])

        self.assertEqual(data, response)

    @unittest.skipUnless(shutil.which("nvim"), "Neovim is required for Tree-sitter analysis")
    def test_treesitter_reports_missing_grammar_clearly(self):
        self.assertFalse(parser_available("xray_missing_grammar"))

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.txt"
            target.write_text("anything\n", encoding="utf-8")
            stat = target.stat()

            with self.assertRaises(AnalysisError) as raised:
                _read_snapshot(
                    str(target), "typescript", "xray_missing_grammar",
                    stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size,
                )

        self.assertIn("Tree-sitter parser unavailable for xray_missing_grammar", str(raised.exception))

    def test_query_error_does_not_leak_banner_to_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "program.c"
            target.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with (
                patch.object(sys, "argv", ["xray", str(target), "--disasm"]),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                code = cli.main()

        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("--disasm requires an ELF binary target", stderr.getvalue())

    def test_missing_target_uses_exit_code_three_and_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-command"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(sys, "argv", ["xray", str(missing), "--report"]),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = cli.main()

        self.assertEqual(status, 3)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Command not found", stderr.getvalue())

    def test_python_syntax_error_uses_exit_code_four_and_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "broken.py"
            target.write_text("def broken(:\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.object(sys, "argv", ["xray", str(target), "--json"]),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = cli.main()

        self.assertEqual(status, 4)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Invalid Python syntax", stderr.getvalue())

    def test_missing_external_analyzers_report_requirements_on_stderr(self):
        original_which = shutil.which
        cases = (
            ("javascript_analyzer", "target.js", "node", "Node.js"),
            ("ruby_analyzer", "target.rb", "ruby", "ruby interpreter"),
            ("treesitter_analyzers", "target.ts", "nvim", "Neovim"),
        )

        with tempfile.TemporaryDirectory() as directory:
            for module, filename, missing_tool, message in cases:
                with self.subTest(tool=missing_tool):
                    target = Path(directory) / filename
                    target.write_text("", encoding="utf-8")
                    stdout = io.StringIO()
                    stderr = io.StringIO()

                    def which(name, missing_tool=missing_tool):
                        return None if name == missing_tool else original_which(name)

                    with (
                        patch(f"xray.{module}.shutil.which", side_effect=which),
                        patch.object(sys, "argv", ["xray", str(target), "--json"]),
                        redirect_stdout(stdout),
                        redirect_stderr(stderr),
                    ):
                        status = cli.main()

                    self.assertEqual(status, 4)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn(message, stderr.getvalue())

    def test_report_shell_command_quotes_paths_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="xray report ") as directory:
            target = Path(directory) / "script.sh"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            expected = f"xray '{target}' --code"

            with patch("xray.report.package_of", return_value=None), \
                    patch("xray.report.overview_lines", return_value=[]), \
                    patch("xray.report.cached_source_files", return_value=None):
                text = "\n".join(report_lines(target))
                markdown = "\n".join(report_lines(target, markdown=True))

        self.assertIn(expected, text)
        self.assertIn(f"`{expected}`", markdown)

    def test_external_relationship_has_no_graph_target_and_keeps_name(self):
        relationship = Edge("/src/main.py", "json", "imports", "external")

        self.assertEqual(
            edge_data(relationship),
            {
                "source": "/src/main.py",
                "target": None,
                "kind": "imports",
                "status": "external",
                "name": "json",
            },
        )

    def test_plain_report_unknown_type_has_no_markdown_bullet(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "unknown"
            target.write_text("data\n", encoding="utf-8")

            with patch("xray.report.command_kind", return_value="unknown"), \
                    patch("xray.report.package_of", return_value=None), \
                    patch("xray.report.overview_lines", return_value=[]), \
                    patch("xray.report.cached_source_files", return_value=None):
                lines = report_lines(target)

        self.assertIn("No source-file listing available for this file type", lines)

    @unittest.skipUnless(shutil.which("ruby"), "Ruby is required for Ruby analysis")
    def test_ruby_methods_keep_owner_and_singleton_kind(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.rb"
            target.write_text(
                "module Box\n class Item\n  def run; end\n"
                "  def self.build; end\n end\nend\n",
                encoding="utf-8",
            )
            symbols = RubyAnalyzer().symbols(target)

        by_name = {symbol.name: symbol for symbol in symbols}
        self.assertEqual(by_name["run"].kind, "method")
        self.assertEqual(by_name["run"].parent, "Box.Item")
        self.assertEqual(by_name["build"].kind, "method")
        self.assertEqual(by_name["build"].parent, "Box.Item")
        self.assertTrue(by_name["build"].metadata["singleton"])

    @unittest.skipUnless(shutil.which("node"), "Node is required for JavaScript analysis")
    def test_javascript_methods_and_nested_functions_keep_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.js"
            target.write_text(
                "class Box { run() { function inside() {} } }\n",
                encoding="utf-8",
            )
            symbols = JavaScriptAnalyzer().symbols(target)

        by_name = {symbol.name: symbol for symbol in symbols}
        self.assertEqual(by_name["run"].kind, "method")
        self.assertEqual(by_name["run"].parent, "Box")
        self.assertEqual(by_name["inside"].parent, "Box.run")

    @unittest.skipUnless(parser_available("typescript"), "Neovim's TypeScript Tree-sitter parser is required")
    def test_typescript_methods_keep_class_and_interface_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.ts"
            target.write_text(
                "interface Contract { save(): void }\n"
                "class Store { save() { function inside() {} } }\n",
                encoding="utf-8",
            )
            symbols = TypeScriptAnalyzer().symbols(target)

        by_name = {(symbol.name, symbol.kind): symbol for symbol in symbols}
        self.assertEqual(by_name[("save", "method")].parent, "Store")
        self.assertEqual(by_name[("inside", "function")].parent, "Store.save")

    @unittest.skipUnless(parser_available("lua"), "Neovim's Lua Tree-sitter parser is required")
    def test_lua_colon_methods_keep_table_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.lua"
            target.write_text("Person = {}\nfunction Person:walk() end\n", encoding="utf-8")
            symbols = LuaAnalyzer().symbols(target)

        method = next(symbol for symbol in symbols if symbol.name == "walk")
        self.assertEqual(method.kind, "method")
        self.assertEqual(method.parent, "Person")


if __name__ == "__main__":
    unittest.main()
