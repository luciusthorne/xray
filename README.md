# XRAY

XRAY inspects local commands, source files, and ELF binaries. It combines static language analyzers, dependency and call graphs, source lookup, and an interactive graph viewer. Results describe what the files and metadata show; they are not proof of runtime behavior.

## Install

Requires Python 3.10 or newer. The Python package has no third-party runtime dependencies. The package is named `xray-trust`; the command it installs is `xray`.

```sh
pipx install xray-trust    # or: python -m pip install xray-trust
xray --help
```

From a checkout: `python -m pip install .`

Install test dependencies and run the full suite:

```sh
python -m pip install '.[test]'
python -m pytest
```

## Quick start

```sh
xray
xray pytest
xray pytest --report
xray pytest --inspect --md > pytest.md
xray pytest --chain
xray pytest --graph-json > pytest-graph.json
xray pytest --html > pytest-graph.html
xray ls --code
xray ls --code main
xray inspect xdg-open
xray why xdg-open glibc
xray scan
xray reach liblzma
```

Running `xray` by itself reads XRAY's own CLI source and suggests follow-up commands. Running `xray <command>` gives that command's overview and suggests code, calls, chains, dependency, cycle, path, and JSON queries. For ELF commands with configured debuginfod, `xray <command> --code` lists function names, and `--code <function>` reads the matching C source.

## Evidence graph: `inspect`, `why`, `scan` and `reach`

`xray inspect <command>` follows everything a command reaches and records the proof for every link: how it was found, where (file and line), and how strong that proof is. It follows:

- shell scripts, read with a full parser (quoting, every expansion, here-documents, `case`, functions, arrays): the commands they run and the files they source, including commands inside `$(...)`, unquoted here-documents, `trap` strings, `sh -c` strings, literal `eval` and wrappers such as `sudo` and `find -exec`;
- Python, Perl, Ruby, JavaScript, TypeScript and Lua imports, and C `#include`s;
- commands Python starts (`subprocess`, `os.system`, `os.exec*`, …, with shell strings parsed) and literal command starts in Ruby, Node and Lua;
- shebang and ELF interpreters, and the shared libraries ELF files need, resolved in the dynamic loader's order: `DT_RPATH`, `LD_LIBRARY_PATH`, `DT_RUNPATH`, the ldconfig cache for the right word size, the default directories, with `$ORIGIN` expanded;
- the package that owns each file.

| Basis | Meaning |
| --- | --- |
| observed | seen in a real run (`--trace`) |
| declared | stated by metadata the system acts on (shebang, ELF `DT_NEEDED`, package database) |
| inferred | read from code, then resolved the way this machine would resolve it |
| guessed | a resolution XRAY can't stand behind: a PATH lookup in a script that changes PATH, or a command run through a variable the script only sets to fixed values |

"Worth a look" lists findings with evidence, such as an empty, relative or world-writable `RPATH`/`RUNPATH` entry that would let another user plant a library.

`xray inspect <command> --tree` prints the whole graph as a tree with the basis and line of every link; it supersedes `--chain` and `--launch`, which remain for compatibility.

`xray why <command> <target>` prints the shortest proof chains from the command to a file, command name, library (`libssl` or `libssl.so.3`) or package; each chain is as strong as its weakest link, and the exit status is 1 when no chain is found. `inspect --trace -- <args>` runs the command and lists files it executed or opened that static reading did not predict.

`xray scan [DIR ...]` reads every executable on PATH (or in the given directories) into an evidence store in `~/.cache/xray` (`$XRAY_CACHE_DIR` overrides it). What each file reaches is stored with its size, times, inode and SHA-256, and with a machine epoch (PATH, the PATH directories and `/etc/ld.so.cache`), so a rescan reads only changed files. The report lists the most reached libraries and every "worth a look" finding with the programs that reach it. `xray reach <target>` then answers the reverse question — which programs reach this file, library, command or package — with the proof chain for each, strongest first.

All four verbs accept `--depth`, `--limit` and `--json` (schema version 1). Every report ends with its blind spots — commands built at runtime (with their lines), files past the depth limit, `LD_PRELOAD` — because a missing link is not proof that something cannot happen. To analyze a file literally named like a verb, pass a path such as `./why`.

## What it reads

| Input | Analysis | Requirements and limits |
| --- | --- | --- |
| Python | AST symbols, imports, references, relationships, call graph, complexity, unused checks, module coupling, and named source spans | Python 3.10+; static analysis only |
| Shell | Commands, sourced files, functions, metrics, and command chains | Static line/token analysis; dynamic commands and `eval` may be unresolved |
| Perl | Literal `use`/`require`, subroutines, and command chains | Perl interpreter improves module resolution |
| JavaScript | Symbols and literal imports/`require` | Node.js with bundled Acorn parser; target source is parsed, not evaluated |
| Ruby | Symbols, methods, and literal imports | Ruby standard-library Ripper; target source is parsed, not evaluated |
| Lua, TypeScript, C | Symbols and imports/includes | Neovim with the relevant Tree-sitter parsers installed |
| ELF | Linked libraries, dynamic symbols, imports, exports, retained function symbols, and command graph | `readelf`; `objdump` for disassembly; `rizin` for annotated function disassembly; configured debuginfod can supply DWARF names and source for stripped binaries |

Package ownership lookup supports RPM and pacman. Named ELF source lookup checks configured local trees, then `libdebuginfod` when `DEBUGINFOD_URLS` is configured, then RPM/DNF source packages. The debuginfod client uses the system cache and limits an individual lookup to 20 seconds and 128 MiB by default; elfutils, a client library, and server-side source data are required. If none provide source, `--code` falls back to labeled machine-code disassembly. Optional system tools include `file`, `strace`, `objdump`, `rizin`, `rpm`, `dnf`, and elfutils.

For packages whose source XRAY cannot retrieve automatically, set `XRAY_SOURCE_PATH` to one or more existing source-tree directories (separated with `:` on Linux). `xray <command> --code <function>` and `--source` search those trees first; `--code` and `--inspect` can list files and functions matched to the binary's available symbols. XRAY reads these directories without executing their build scripts. On systems with configured debuginfod servers, XRAY can also use ELF build IDs and DWARF line tables to fetch the exact source file for a named function, without running package scripts.

## CLI reference

Run `xray --help` for descriptions and argument forms. The options are grouped here by purpose:

- Inspection: `--report`, `--inspect`, `--md`, `--code`, `--browse`, `--asm`, `--source`, `--source-cache-list`, `--source-cache-remove`, `--source-cache-clear`, `--disasm-function`, `--package`, `--toolchain`, `--serve`.
- Commands and binaries: `--calls`, `--chain`, `--launch`, `--launch-depth`, `--launch-limit`, `--shell-metrics`, `--uses`, `--disasm`, `--trace`.
- Graph queries: `--deps`, `--dependents`, `--tree`, `--impact`, `--cycles`, `--depth`, `--project`, `--components`, `--reachable`, `--reverse-reachable`, `--path`, `--changes`.
- Source analysis: `--symbols`, `--references`, `--relationships`, `--unused`, `--complexity`, `--callgraph`, `--unused-symbols`, `--coupling`, `--call-coupling`.
- Exports and help: `--json`, `--graph-json`, `--html`, `--version`, `--help`.

`--report` and `--inspect` show command identity, overview, and available source files. Add `--md` for Markdown. `--json` exports one file; `--graph-json` exports a bounded command graph. `--html` writes a self-contained viewer. `--serve` binds to loopback and rejects non-loopback `Host` headers.

Project dependency queries use the registered analyzers to include supported Python, shell, Perl, Ruby, JavaScript, Lua, TypeScript, and C source files. Resolved imports and locally sourced files connect nodes in the project graph; external and unresolved dependencies are listed separately from file-to-file counts.

`xray <file-in-repo> --changes [<base-ref>]` compares the working tree, including staged, unstaged, and untracked files, with a Git commit or ref (default `HEAD`). It lists current in-project dependents of changed source files when the project graph can resolve them.

Downloaded RPM source trees can be listed with `xray --source-cache-list`, removed individually with `xray --source-cache-remove <package>`, or cleared with `xray --source-cache-clear`. These commands operate only on `src/`; parser results under `analysis/` are separate. Set `XRAY_SOURCE_CACHE_MAX_MIB` to a non-negative integer to prune least-recently-used cached trees after a successful download; unset it for no size limit. The currently requested tree is kept even if it alone exceeds the limit. Extraction is staged before becoming visible, and cache mutation and source reads are serialized between XRAY processes.

## JSON contracts

`--browse` is a terminal menu over the same views: overview, functions (pick one by number or name to read its code), calls, chain, and for ELF binaries toolchain and uses. It needs an interactive terminal; `--serve` is the browser equivalent.

`--toolchain` reads an ELF binary without running it and names the language that built it: Go (toolchain, main module, dependencies with replacements, and build settings from `.go.buildinfo`), Rust (rustc version from `.comment` and crate versions from retained registry paths; distributions that remap paths keep no crate list), C++, Fortran, D, Haskell, Swift, Objective-C (by their runtime libraries), C, or a PyInstaller bundle, plus the compilers recorded in `.comment`. When `.comment` was stripped and only the C library is linked, the result is labelled `C (inferred)` with the reason. `--report` and `--inspect` show the same language on their Identity line.

Any text query also accepts a trailing `--json` (for example `xray ls --inspect --json` or `xray tool.sh --calls --json`). The output has `schema_version`, `query`, `target`, `title`, and `sections`; each section has a `heading` (null for text before the first heading), `fields` (`Key: value` lines, with lists for keys followed by `- item` lines), `items` (other `- item` lines), and `lines` (anything else). It cannot be combined with `--md`, `--html`, `--serve`, or `--graph-json`. Errors still go to stderr with the usual exit codes.

Single-file `--json` includes `schema_version`, file identity, analyzer, symbols, edges, notes, and metadata. `--graph-json` includes a root, nodes, edges, and traversal limits and truncation metadata. External and unresolved edges preserve their written name and use a null target when no file resolves.

## Safety and limits

Static analyzers read source without executing it. For ELF binaries, `--code` lists available function names from configured debuginfod when possible; request a name to read its source. Without source data, it displays bounded `objdump` machine code. `--trace` runs the selected command under `strace`, discards its output, and stops it after ten seconds; use it only when running that command is appropriate. `--uses` reports symbols a binary may call, not proof that it calls them at runtime.

Named Python functions, async functions, classes, and qualified methods use AST spans including decorators, capped at 400 lines. Other script analyzers show the whole definition, using the end line reported by their parser (JavaScript, TypeScript, Ruby, Lua, C) or the matching closing brace (shell, Perl), capped at 400 lines; when no end is found, up to 60 lines are shown and labelled as such. ELF source lookup uses available debug/source data; when source is unavailable, `--code` displays bounded `objdump` disassembly and labels it as machine code rather than source.

## Project structure

```text
xray/
├── __init__.py
├── __main__.py
├── analysis_cache.py
├── analysis_views.py
├── analyze.py
├── analyzers.py
├── browse.py
├── callgraph.py
├── calls.py
├── chain.py
├── classify.py
├── cli.py
├── codeview.py
├── command_analyzers.py
├── commandproject.py
├── complexity.py
├── coupling.py
├── dependencies.py
├── debuginfod.py
├── disasm.py
├── discover.py
├── elfscan.py
├── entrypoints.py
├── errors.py
├── evidence.py
├── evidencestore.py
├── export.py
├── fingerprint.py
├── graph.py
├── graphjson.py
├── git_analysis.py
├── html.py
├── identify.py
├── javascript_analyzer.py
├── launchgraph.py
├── libresolve.py
├── locate.py
├── minidebug.py
├── model.py
├── overview.py
├── perlscan.py
├── project_graph.py
├── provenance.py
├── pyexec.py
├── python_analyzer.py
├── references.py
├── relationships.py
├── report.py
├── rizinview.py
├── ruby_analyzer.py
├── scan.py
├── serve.py
├── shellmetrics.py
├── shellscan.py
├── shparse.py
├── sourcelookup.py
├── symbols.py
├── textjson.py
├── trace.py
├── treesitter_analyzers.py
├── unused.py
├── unused_symbols.py
├── uses.py
└── verbs.py
```

## Testing

The full suite uses pytest and includes upstream regression tests plus audit regressions. Install it with `python -m pip install '.[test]'`, then run `python -m pytest`. Some integration tests skip when optional system tools are unavailable. CI runs Ruff across the package and test tree, and runs the full suite across Python 3.10–3.15 and a Fedora integration job.

## License

Apache-2.0. See `LICENSE`.
