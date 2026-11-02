"""Lua, TypeScript, and C readers backed by Neovim's Tree-sitter parsers."""

import json
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from .analyzers import Analyzer, registry
from .errors import AnalysisError, FileError
from .javascript_analyzer import _resolve as _resolve_node_modules
from .model import Edge
from .symbols import Symbol

_NVIM_READER = r"""
local lang = vim.env.XRAY_PARSE_LANGUAGE
local ok, parser = pcall(vim.treesitter.get_parser, 0, lang)
if not ok then
  print(vim.json.encode({error = 'Tree-sitter parser unavailable for ' .. lang .. ': ' .. tostring(parser)}))
  return
end
local parsed_ok, trees = pcall(parser.parse, parser)
if not parsed_ok or not trees or not trees[1] then
  print(vim.json.encode({error = 'Tree-sitter could not parse this source'}))
  return
end
local root = trees[1]:root()
if root:has_error() then
  print(vim.json.encode({error = 'source contains syntax errors'}))
  return
end
local symbols, imports = {}, {}
local function field(node, wanted)
  for child, name in node:iter_children() do
    if name == wanted then return child end
  end
  return nil
end
local function text(node)
  if not node then return '' end
  return vim.treesitter.get_node_text(node, 0)
end
local function literal(node)
  if not node or (node:type() ~= 'string' and node:type() ~= 'string_literal') then return nil end
  local pieces = {}
  for child in node:iter_children() do
    local kind = child:type()
    if kind == 'string_fragment' or kind == 'string_content' then
      table.insert(pieces, text(child))
    elseif child:named() then
      return nil
    end
  end
  if #pieces == 0 then return nil end
  local value = table.concat(pieces)
  if value:find('\\', 1, true) then return nil end
  return value
end
local function qualify(parent, name)
  if parent and parent ~= '' then return parent .. '.' .. name end
  return name
end
local function add_symbol(node, name_node, kind, parent, name_override)
  local name = name_override or text(name_node)
  if name ~= '' then
    local row = node:range()
    table.insert(symbols, {name = name, kind = kind, line = row + 1, parent = parent})
  end
end
local function first_literal(node)
  if node:type() == 'string' or node:type() == 'string_literal' then return literal(node) end
  for child in node:iter_children() do
    local value = first_literal(child)
    if value then return value end
  end
  return nil
end
local function first_type(node, wanted)
  if node:type() == wanted then return node end
  for child in node:iter_children() do
    local found = first_type(child, wanted)
    if found then return found end
  end
  return nil
end
local function walk(node, parent)
  local kind = node:type()
  local child_parent = parent
  if kind == 'function_declaration' then
    local name = field(node, 'name')
    if lang == 'lua' and name and (name:type() == 'method_index_expression'
      or name:type() == 'dot_index_expression') then
      local owner = field(name, 'table')
      local method = field(name, 'method') or field(name, 'field')
      if owner and method then
        local owner_name = text(owner)
        add_symbol(node, method, 'method', owner_name)
        child_parent = qualify(owner_name, text(method))
      else
        local raw = text(name)
        local owner_text, method_text = raw:match('^(.-)[:%.]([^%.:]+)$')
        if owner_text and method_text then
          add_symbol(node, name, 'method', owner_text, method_text)
          child_parent = qualify(owner_text, method_text)
        else
          add_symbol(node, name, 'function', parent)
        end
      end
    else
      add_symbol(node, name, 'function', parent)
    end
  elseif kind == 'class_declaration' then
    local name = field(node, 'name')
    add_symbol(node, name, 'class', parent)
    child_parent = qualify(parent, text(name))
  elseif kind == 'method_definition' then
    local name = field(node, 'name')
    add_symbol(node, name, 'method', parent)
    child_parent = qualify(parent, text(name))
  elseif kind == 'method_signature' then
    local name = field(node, 'name')
    add_symbol(node, name, 'method', parent)
  elseif kind == 'interface_declaration' then
    local name = field(node, 'name')
    add_symbol(node, name, 'interface', parent)
    child_parent = qualify(parent, text(name))
  elseif kind == 'type_alias_declaration' then
    local name = field(node, 'name')
    add_symbol(node, name, 'type', parent)
    child_parent = qualify(parent, text(name))
  elseif lang == 'c' and kind == 'function_definition' then
    local declarator = field(node, 'declarator')
    local fn = declarator and first_type(declarator, 'function_declarator') or nil
    local name = fn and first_type(field(fn, 'declarator') or fn, 'identifier') or nil
    add_symbol(node, name, 'function', parent)
  elseif lang == 'c' and (kind == 'struct_specifier' or kind == 'union_specifier'
    or kind == 'enum_specifier') then
    local name = field(node, 'name')
    add_symbol(node, name, 'type', parent)
    child_parent = qualify(parent, text(name))
  elseif kind == 'variable_declarator' then
    local value = field(node, 'value')
    if value and (value:type() == 'arrow_function' or value:type() == 'function_expression'
      or value:type() == 'class') then
      local name = field(node, 'name')
      local symbol_kind = value:type() == 'class' and 'class' or 'function'
      add_symbol(node, name, symbol_kind, parent)
      if symbol_kind == 'class' then child_parent = qualify(parent, text(name)) end
    end
  end

  if lang == 'c' and kind == 'preproc_include' then
    local include = field(node, 'path')
    if include and include:type() == 'system_lib_string' then
      local name = text(include):match('^<(.+)>$')
      if name then table.insert(imports, {name = name, kind = 'imports', system = true}) end
    elseif include then
      local name = literal(include)
      if name then table.insert(imports, {name = name, kind = 'imports', system = false}) end
    end
  elseif lang ~= 'lua' and (kind == 'import_statement' or kind == 'export_statement') then
    local source = field(node, 'source')
    local name = literal(source)
    if name then table.insert(imports, {name = name, kind = 'imports'}) end
  elseif (lang == 'lua' and kind == 'function_call') or (lang ~= 'lua' and kind == 'call_expression') then
    local callee = field(node, lang == 'lua' and 'name' or 'function')
    local name = text(callee)
    if (lang == 'lua' and name == 'require') or (lang ~= 'lua' and (name == 'require' or name == 'import')) then
      local args = field(node, 'arguments')
      local specifier = args and first_literal(args) or nil
      if specifier then table.insert(imports, {name = specifier, kind = 'imports'}) end
    end
  end

  for child in node:iter_children() do walk(child, child_parent) end
end
walk(root, nil)
local metadata = vim.treesitter.language.inspect(lang)
local grammar = metadata.metadata or {}
print(vim.json.encode({symbols = symbols, imports = imports,
  parser_version = table.concat({metadata.abi_version, grammar.major_version or 0,
    grammar.minor_version or 0, grammar.patch_version or 0}, '.') }))
"""


def _json_payload(lines):
    """Return the Tree-sitter JSON response, ignoring Neovim log noise."""
    for line in reversed(lines):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(data, dict) and (
            "error" in data
            or (isinstance(data.get("symbols"), list)
                and isinstance(data.get("imports"), list))
        ):
            return data

    return None


def _language(path, kind):
    if kind == "typescript" and path.suffix == ".tsx":
        return "tsx"
    return kind


def _read(path, kind):
    path = Path(path).resolve()

    try:
        stat = path.stat()
    except OSError as error:
        raise FileError(f"Unable to read file: {path}") from error

    return _read_snapshot(
        str(path), kind, _language(path, kind), stat.st_mtime_ns,
        stat.st_ctime_ns, stat.st_size,
    )


@lru_cache(maxsize=128)
def _read_snapshot(path_text, kind, language, _mtime_ns, _ctime_ns, _size):
    path = Path(path_text)

    try:
        path.read_text(encoding="utf-8")
    except OSError as error:
        raise FileError(f"Unable to read file: {path}") from error
    except UnicodeError as error:
        raise FileError(f"Unable to decode file: {path}") from error

    nvim = shutil.which("nvim")

    if nvim is None:
        raise AnalysisError(f"{kind.title()} analysis requires Neovim with Tree-sitter support")

    env = os.environ.copy()
    env["XRAY_PARSE_LANGUAGE"] = language

    try:
        result = subprocess.run(
            [nvim, "--headless", "-u", "NONE", "-i", "NONE", "--noplugin",
             "-n", "-R", "--cmd", "set nomodeline noswapfile updatecount=0",
             str(path), "-c", "lua " + _NVIM_READER, "-c", "qa!"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AnalysisError(f"Tree-sitter parser failed for {path}: {error}") from error

    if result.returncode != 0:
        raise AnalysisError(f"Tree-sitter parser failed for {path}: {result.stderr.strip()}")

    lines = [
        line for line in (result.stdout + "\n" + result.stderr).splitlines()
        if line.strip()
    ]

    data = _json_payload(lines)
    if data is None:
        raise AnalysisError(f"Tree-sitter returned invalid data for {path}")

    if "error" in data:
        raise AnalysisError(f"Unable to analyze {path}: {data['error']}")

    return path, kind, data


def _module_file(root, name, patterns):
    module_path = Path(name.replace(".", os.sep))
    for pattern in patterns:
        candidate = Path(pattern.replace("?", str(module_path)))
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.is_file():
            return candidate.resolve()
    return None


@lru_cache(maxsize=1)
def _lua_paths():
    lua = shutil.which("lua")
    if lua is None:
        return (), ()

    try:
        result = subprocess.run(
            [lua, "-e", "io.write(package.path, '\\n', package.cpath)"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return (), ()

    if result.returncode != 0:
        return (), ()

    parts = result.stdout.splitlines()
    paths = tuple(parts[0].split(";")) if parts else ()
    cpaths = tuple(parts[1].split(";")) if len(parts) > 1 else ()
    return paths, cpaths


LUA_BUILTINS = {"assert", "coroutine", "debug", "io", "math", "os", "package", "string", "table", "utf8"}


class LuaAnalyzer(Analyzer):
    name = "lua"
    kinds = ("lua",)

    def symbols(self, path):
        path, _kind, data = _read(path, self.name)
        return [
            Symbol(item["name"], item["kind"], str(path), item["line"], item.get("parent"))
            for item in data["symbols"]
        ]

    def edges(self, path):
        path, _kind, data = _read(path, self.name)
        lua_paths, c_paths = _lua_paths()
        found = []

        for item in data["imports"]:
            name = item["name"]
            target = _module_file(path.parent, name, ("?.lua", "?/init.lua"))

            if target is None:
                for pattern in (*lua_paths, *c_paths):
                    target = _module_file(Path.cwd(), name, (pattern,))
                    if target is not None:
                        break

            if target is not None:
                found.append(Edge(str(path), str(target), "imports", "resolved", name=name))
            elif name in LUA_BUILTINS:
                found.append(Edge(str(path), name, "imports", "external", name=name))
            else:
                found.append(Edge(str(path), None, "imports", "unresolved", name=name))

        return found


class TypeScriptAnalyzer(Analyzer):
    name = "typescript"
    kinds = ("typescript",)

    def symbols(self, path):
        path, _kind, data = _read(path, self.name)
        return [
            Symbol(item["name"], item["kind"], str(path), item["line"], item.get("parent"))
            for item in data["symbols"]
        ]

    def edges(self, path):
        path, _kind, data = _read(path, self.name)
        found = []
        unresolved = []
        extensions = ("", ".ts", ".tsx", ".d.ts", ".js", ".mjs", ".cjs", ".json")

        for item in data["imports"]:
            name = item["name"]
            specifier = Path(name)
            target = None

            if name.startswith((".", "/")):
                base = specifier if specifier.is_absolute() else path.parent / specifier
                bases = [base]

                if base.suffix in {".js", ".jsx", ".mjs", ".cjs"}:
                    bases.extend(base.with_suffix(ext) for ext in (".ts", ".tsx", ".d.ts"))

                for candidate_base in bases:
                    for suffix in extensions:
                        candidate = (
                            Path(str(candidate_base) + suffix)
                            if suffix and not candidate_base.suffix
                            else candidate_base
                        )

                        if candidate.is_file():
                            target = candidate.resolve()
                            break

                        if candidate.is_dir():
                            for index_name in ("index.ts", "index.tsx", "index.d.ts", "index.js"):
                                index_candidate = candidate / index_name
                                if index_candidate.is_file():
                                    target = index_candidate.resolve()
                                    break

                        if target is not None:
                            break

                    if target is not None:
                        break

            if target is not None:
                found.append(Edge(str(path), str(target), "imports", "resolved", name=name))
            else:
                unresolved.append(item)

        if unresolved:
            if shutil.which("node") is None:
                found.extend(
                    Edge(str(path), None, "imports", "unresolved", name=item["name"])
                    for item in unresolved
                )
            else:
                resolved = _resolve_node_modules(path, unresolved)
                for item in resolved:
                    found.append(Edge(
                        str(path), item["target"], "imports", item["status"],
                        name=item["name"],
                    ))

        return found


class CAnalyzer(Analyzer):
    name = "c"
    kinds = ("c",)

    def symbols(self, path):
        path, _kind, data = _read(path, self.name)
        return [
            Symbol(item["name"], item["kind"], str(path), item["line"], item.get("parent"))
            for item in data["symbols"]
        ]

    def edges(self, path):
        path, _kind, data = _read(path, self.name)
        found = []

        for item in data["imports"]:
            name = item["name"]

            if item.get("system"):
                found.append(Edge(
                    str(path), name, "imports", "external", name=name
                ))
                continue

            candidate = path.parent / name

            if candidate.is_file():
                found.append(Edge(
                    str(path), str(candidate.resolve()), "imports", "resolved", name=name
                ))
            else:
                found.append(Edge(
                    str(path), None, "imports", "unresolved", name=name
                ))

        return found


for _analyzer in (LuaAnalyzer(), TypeScriptAnalyzer(), CAnalyzer()):
    if _analyzer.name not in registry.names():
        registry.register(_analyzer)
