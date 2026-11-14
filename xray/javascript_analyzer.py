"""JavaScript source reader using Node's bundled Acorn parser.

Node parses the source supplied on stdin. The target and its imports are
never evaluated. Only literal static imports and require calls are followed.
"""

import json
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from .analysis_cache import get_or_compute
from .analyzers import Analyzer, registry
from .errors import AnalysisError, FileError
from .model import Edge
from .symbols import Symbol

_NODE_READER = r"""
const fs = require('node:fs');
let acornParser;
const natives = process.binding('natives');
const acornSource = natives['internal/deps/acorn/acorn/dist/acorn'];
if (!acornSource) {
  process.stdout.write(JSON.stringify({error: 'Node does not expose its bundled Acorn parser'}));
  process.exit(0);
}
const acorn = {exports: {}};
Function('exports', 'require', 'module', acornSource)(acorn.exports, require, acorn);
acornParser = acorn.exports;
const source = fs.readFileSync(0, 'utf8');
let ast;
try {
  ast = acornParser.parse(source, {ecmaVersion: 'latest', sourceType: 'module', locations: true, allowHashBang: true});
} catch (moduleError) {
  try {
    ast = acornParser.parse(source, {ecmaVersion: 'latest', sourceType: 'script', locations: true, allowHashBang: true});
  } catch (scriptError) {
    process.stdout.write(JSON.stringify({error: scriptError.message}));
    process.exit(0);
  }
}
const symbols = [];
const imports = [];
function addImport(specifier, kind) {
  if (typeof specifier !== 'string') return;
  imports.push({name: specifier, kind});
}
function qualify(parent, name) {
  return parent ? `${parent}.${name}` : name;
}
function walk(node, parent = null) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { node.forEach(child => walk(child, parent)); return; }
  let childParent = parent;
  switch (node.type) {
    case 'FunctionDeclaration':
      if (node.id) {
        symbols.push({name: node.id.name, kind: 'function', line: node.loc.start.line, end: node.loc.end.line, start: node.start, stop: node.end, parent});
        childParent = qualify(parent, node.id.name);
      }
      break;
    case 'ClassDeclaration':
      if (node.id) {
        symbols.push({name: node.id.name, kind: 'class', line: node.loc.start.line, end: node.loc.end.line, start: node.start, stop: node.end, parent});
        childParent = qualify(parent, node.id.name);
      }
      break;
    case 'MethodDefinition':
      if (node.key && (node.key.type === 'Identifier' || node.key.type === 'PrivateIdentifier')) {
        symbols.push({name: node.key.name, kind: 'method', line: node.loc.start.line, end: node.loc.end.line, start: node.start, stop: node.end, parent});
        childParent = qualify(parent, node.key.name);
      }
      break;
    case 'VariableDeclarator':
      if (node.id.type === 'Identifier' && node.init &&
          ['FunctionExpression', 'ArrowFunctionExpression', 'ClassExpression'].includes(node.init.type)) {
        const kind = node.init.type === 'ClassExpression' ? 'class' : 'function';
        symbols.push({name: node.id.name, kind, line: node.loc.start.line, end: node.loc.end.line, start: node.start, stop: node.end, parent});
        childParent = qualify(parent, node.id.name);
      }
      break;
    case 'ImportDeclaration':
    case 'ExportNamedDeclaration':
    case 'ExportAllDeclaration':
      if (node.source) addImport(node.source.value, 'imports');
      break;
    case 'ImportExpression':
      if (node.source && node.source.type === 'Literal') addImport(node.source.value, 'imports');
      break;
    case 'CallExpression':
      if (node.callee && node.callee.type === 'Identifier' && node.callee.name === 'require' &&
          node.arguments.length === 1 && node.arguments[0].type === 'Literal')
        addImport(node.arguments[0].value, 'imports');
      break;
  }
  for (const key of Object.keys(node)) {
    if (key !== 'loc' && key !== 'start' && key !== 'end') walk(node[key], childParent);
  }
}
walk(ast);
const uniqueSymbols = [...new Map(symbols.map(s => [`${s.kind}:${s.name}:${s.line}`, s])).values()];
const uniqueImports = [...new Map(imports.map(i => [`${i.kind}:${i.name}`, i])).values()];
process.stdout.write(JSON.stringify({symbols: uniqueSymbols, imports: uniqueImports}));
"""

_NODE_RESOLVER = r"""
const path = require('node:path');
const Module = require('node:module');
const filename = path.resolve(process.argv[1]);
const requests = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const req = Module.createRequire(filename);
const result = requests.map(item => {
  const specifier = item.name;
  if (Module.isBuiltin(specifier) || Module.isBuiltin(specifier.replace(/^node:/, '')))
    return {...item, target: specifier, status: 'external'};
  try {
    return {...item, target: req.resolve(specifier), status: 'resolved'};
  } catch (_) {
    return {...item, target: null, status: 'unresolved'};
  }
});
process.stdout.write(JSON.stringify(result));
"""

_NODE_PARSER_VERSION = r"""
const source = process.binding('natives')['internal/deps/acorn/acorn/dist/acorn'];
if (!source) { process.stdout.write('unavailable'); process.exit(0); }
const module = {exports: {}};
Function('exports', 'require', 'module', source)(module.exports, require, module);
const parser = module.exports;
process.stdout.write(String(parser.version || 'unknown'));
"""


def _read(path):
    path = Path(path).resolve()

    try:
        stat = path.stat()
    except OSError as error:
        raise FileError(f"Unable to read file: {path}") from error

    return path, _read_snapshot(
        str(path), stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size
    )


@lru_cache(maxsize=128)
def _read_snapshot(path_text, _mtime_ns, _ctime_ns, _size):
    path = Path(path_text)

    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise FileError(f"Unable to read file: {path}") from error
    except UnicodeError as error:
        raise FileError(f"Unable to decode file: {path}") from error

    node = shutil.which("node")

    if node is None:
        raise AnalysisError("JavaScript analysis requires Node.js")

    try:
        version = subprocess.run(
            [node, "-e", _NODE_PARSER_VERSION], capture_output=True, text=True,
            timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AnalysisError(f"Unable to identify Node parser version: {error}") from error

    if version.returncode != 0 or version.stdout.strip() == "unavailable":
        raise AnalysisError("Unable to identify Node parser version")

    def compute():
        try:
            result = subprocess.run(
                [node, "-e", _NODE_READER, str(path)],
                input=source,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AnalysisError(f"JavaScript parser failed for {path}: {error}") from error

        if result.returncode != 0:
            raise AnalysisError(f"JavaScript parser failed for {path}: {result.stderr.strip()}")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise AnalysisError(f"JavaScript parser returned invalid data for {path}") from error

        if "error" in data:
            raise AnalysisError(f"Invalid JavaScript syntax in {path}: {data['error']}")

        return data

    return get_or_compute(
        "javascript", version.stdout.strip() + ":acorn-scan-v3",
        source.encode("utf-8"), compute,
    )


def _resolve(path, imports):
    if not imports:
        return []

    node = shutil.which("node")
    requests = json.dumps(imports)

    try:
        result = subprocess.run(
            [node, "-e", _NODE_RESOLVER, str(path)],
            input=requests,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AnalysisError(f"JavaScript module resolution failed for {path}: {error}") from error

    if result.returncode != 0:
        raise AnalysisError(f"JavaScript module resolution failed for {path}: {result.stderr.strip()}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AnalysisError(f"JavaScript resolver returned invalid data for {path}") from error


def _end_metadata(item):
    """Symbol metadata holding the definition's last line, when the parser gave one."""
    end = item.get("end")
    metadata = {"end_line": end} if isinstance(end, int) else {}
    if isinstance(item.get("start"), int) and isinstance(item.get("stop"), int):
        metadata["offsets"] = (item["start"], item["stop"])  # UTF-16 code units, from the parser
    return metadata


class JavaScriptAnalyzer(Analyzer):
    """Read JavaScript symbols and statically declared module dependencies."""

    name = "javascript"
    kinds = ("javascript",)

    def symbols(self, path):
        path, data = _read(path)
        return [
            Symbol(
                item["name"], item["kind"], str(path), item["line"],
                item.get("parent"), _end_metadata(item),
            )
            for item in data["symbols"]
        ]

    def edges(self, path):
        path, data = _read(path)
        imports = _resolve(path, data["imports"])
        return [
            Edge(
                str(path),
                item["target"],
                item["kind"],
                item["status"],
                name=item["name"],
            )
            for item in imports
        ]


if "javascript" not in registry.names():
    registry.register(JavaScriptAnalyzer())
