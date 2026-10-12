# xray

xray is a lightweight static-analysis tool for Python projects and for the commands installed on your system.

It builds a dependency graph of a Python project, reads the code inside it, and can follow a command such as `pytest` into the code it launches.

Think of it as a small X-ray machine for your codebase.

## What it can do

- **Dependency graph:** dependencies, dependents, trees, impact analysis, cycles, depth, reachability, paths and strongly connected components.
- **Commands:** follow a launcher into the installed code it runs, and show the tree of what a script or binary runs.
- **Static analysis of Python:** symbols, references, relationships, unused imports, unused symbols and complexity.
- **Architecture metrics:** a static call graph, module coupling and call coupling.
- **Command overview:** `xray <command>` shows what a shell script runs, what an ELF binary links to, and the installed code behind a Python launcher.
- **Shell scripts:** approximate complexity metrics with `--shell-metrics`.
- **JSON export:** `--json` prints the symbols and edges of a file as data.

## Installation

From the project directory:

```
pip install -e .
```

## Usage

```
xray <target> [option]
```

The target is a file path or the name of a command found on your `PATH`. Without an option, xray prints the file type and size. Python files get a short summary. Shell scripts, ELF binaries and Python launchers get an **Overview** section:

- a shell script lists its functions, the files it sources and the external commands it runs, with where each resolves to
- an ELF binary lists its interpreter, the shared libraries it links to and the symbols it imports
- a Python launcher (a Python command without a `.py` suffix, such as `pytest`) lists the installed file it runs

If a shell script has no external commands that static reading can see, the overview says so, because commands run through variables or `eval` are not visible.

You can also run it as a module:

```
python -m xray <target> [option]
```

Other flags:

```
xray --help       # or -h
xray --version    # or -V
```

## Dependency-graph options

| Option | Shows |
|---|---|
| `--deps` | what the file depends on |
| `--dependents` | which files depend on it |
| `--tree` | the dependency tree |
| `--impact` | directly and indirectly affected files, and impact chains |
| `--cycles` | circular dependencies involving the file |
| `--depth` | the maximum dependency depth |
| `--project` | file count, dependency edges, leaf files, cycles and hotspots |
| `--components` | strongly connected components |
| `--reachable` | everything reachable from the file |
| `--reverse-reachable` | everything that can reach the file |
| `--path <target>` | the shortest dependency path to another file, or `No path found` |

Example:

```
xray test_programs/cycle_a.py --path test_programs/cycle_c.py
cycle_a.py → cycle_b.py → cycle_c.py
```

## Command options

These work on scripts and binaries, including commands found on `PATH`.

| Option | Shows |
|---|---|
| `--launch` | the installed code a Python launcher runs |
| `--launch-depth` | the same, following imports further down |
| `--launch-limit` | the same, with a cap on how many files are listed |
| `--calls` | what a script or binary runs |
| `--chain` | the tree of what a command runs |
| `--package` | the installed package that owns the file (uses rpm) |
| `--html` | one self-contained HTML page that draws the same graph as `--graph-json`, with zoom, pan, dragging, click-to-inspect, a search box, kind filters, cycle highlighting, shift-click shortest paths, impact highlighting and a per-node summary of reach, impact and cycles; save it with `xray tool --html > graph.html` and open it in a browser; works offline |
| `--graph-json` | the whole graph of what a command runs, sources, imports or links to, as JSON: nodes (kind, package, symbol count), edges (with names) and metadata; stops at depth 5 and 100 files and says when it did |
| `--uses` | the symbols an ELF binary imports, grouped by purpose (files, memory, network, ...); a name means the binary can call it, not that it does at run time; the default view shows a one-line summary |
| `--disasm-function <name>` | one function of an ELF binary as annotated disassembly (arguments, cross-references), read through rizin; the name must be one of the function names from `.gnu_debugdata`, and the binary is never run |
| `--disasm` | which functions an ELF binary calls directly, read from `objdump -d` without running it, with function names from `.gnu_debugdata` when the binary has them; imports are marked, and indirect calls and calls into the middle of a function are counted but not resolved |
| `--trace` | **runs the command** under strace and shows the programs it executes and the files it opens; pass its arguments after `--`, as in `xray tool --trace -- arg` (needs strace, stops after 10 seconds) |

`--chain` expands shell scripts into the commands they run, Python launchers into the installed files they import, and ELF binaries into the libraries they need. Each line reads `name -> resolved path [kind]`. A file that appears again is marked `(seen)` and is not expanded again, and a name that cannot be found is marked `(not found)`. The tree has a depth limit and a file limit, and a final `Truncated:` line says when something was left out.

## Static-analysis options

These analyze Python code. On a target that is not a Python file they exit with code 3.

| Option | Scope | Shows |
|---|---|---|
| `--symbols` | the file | functions, classes and methods |
| `--references` | the file | where imported names are used and what they resolve to |
| `--relationships` | the file | calls and inheritance |
| `--unused` | the file | imports that appear unused |
| `--complexity` | the file | lines, functions, cyclomatic complexity and nesting |
| `--callgraph` | the file | which functions each function calls |
| `--unused-symbols` | the whole folder | definitions that appear to have no references |
| `--coupling` | the whole folder | fan-in, fan-out, density and the most coupled modules |
| `--call-coupling` | the whole folder | calls in and out of each module |
| `--shell-metrics` | a shell script | functions, approximate complexity and nesting |
| `--json` | the file | symbols and edges as JSON (Python, shell, ELF), with no banner |

## JSON export

`xray <target> --json` prints one JSON object and nothing else (no banner), so it can be piped into tools such as `jq`:

```
xray ldd --json
```

| Field | Meaning |
|---|---|
| `file` | the resolved path |
| `kind` | `python`, `shell`, `elf`, `perl`, `script` or `unknown` |
| `analyzer` | the analyzer that read the file, or `null` |
| `symbols` | name, kind, line and parent (Python only) |
| `edges` | source, target, kind and status |
| `notes` | caveats, such as no visible shell commands |

Edge kinds include `imports`, `calls`, `inherits`, `references`, `runs`, `sources` and `links`. The status is `resolved`, `unresolved` or `external`.

## Output and exit codes

Normal results go to stdout. Errors are written to stderr as `Error: ...`.

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | general error or unexpected crash |
| 2 | invalid command-line usage |
| 3 | target or file error |
| 4 | analysis error |

## Limitations

Python is dynamic, so xray reports what static analysis can see and does not claim perfect accuracy.

- Dynamic imports, `getattr` and names built from strings are not seen. The unused-import and unused-symbol results are hints, not proof.
- `--unused-symbols` cannot see use from outside the analyzed folder, such as a public API.
- The call graph is conservative: only calls that resolve to a definition become `->` edges, and calls it recorded but could not resolve are marked `?`.
- Calls through a project module (`utils.calculate()` after `import utils`, `import utils as u`, `import pkg.sub` or `from pkg import sub`) are resolved. Calls into external modules, such as `os.getcwd()`, are not recorded.
- For ELF binaries, xray lists the libraries and symbols they use. It does not read the machine code.
- Shell metrics are approximate. Keywords are counted after removing comments, quoted text and heredocs.
- Perl and other scripts are recognized but not read yet.

The count of shell commands run through variables or `eval` can overstate hidden commands: a test such as `if $flag` runs a variable as a command, so it is counted even when the variable only holds `true` or `false`.

## How it works

At its core, xray builds a directed dependency graph. A dependency such as `a.py → b.py` means that `a.py` depends on `b.py`. Cycle detection, reachability, path finding, impact analysis and the other graph options all run on that one representation. The static-analysis options read the Python AST and combine the results with the graph.

## Project structure

```
xray/
├── __init__.py         package version
├── __main__.py         python -m xray entry point
├── cli.py              command-line interface and query dispatch
├── errors.py           error types and exit codes
├── graph.py            dependency graph engine
├── analyze.py          Python source analysis
├── discover.py         target resolution
├── identify.py         file identification
├── classify.py         shebang and file classification
├── dependencies.py     dependency extraction
├── symbols.py          functions, classes and methods
├── references.py       references and their targets
├── relationships.py    calls and inheritance
├── callgraph.py        static call graph
├── unused.py           unused imports
├── unused_symbols.py   unused definitions
├── complexity.py       complexity and nesting metrics
├── coupling.py         module and call coupling
├── analysis_views.py   text output for the analyses above
├── entrypoints.py      command kinds and the modules a command imports
├── launchgraph.py      launcher to installed code
├── shellscan.py        shell script reader
├── elfscan.py          ELF binary reader
├── libresolve.py       shared library resolution
├── calls.py            what a script or binary runs
├── chain.py            tree of what a command runs
├── model.py            common types: FileInfo and Edge
├── analyzers.py        analyzer base class and registry
├── python_analyzer.py  Python files as symbols and edges
├── command_analyzers.py  shell scripts and ELF binaries as edges
├── overview.py         the Overview section of the default view
├── shellmetrics.py     approximate shell script metrics
├── export.py           the data behind --json
├── locate.py           command name to file
├── provenance.py       the package that owns a file (rpm)
├── trace.py            run a command under strace
├── minidebug.py        function names kept in stripped ELF files
├── disasm.py           direct calls inside an ELF binary (objdump)
├── uses.py             imports grouped by purpose and by library
├── graphjson.py        the whole graph of a command as data
├── html.py             the interactive graph page
└── rizinview.py        one function as annotated disassembly (rizin)
```

## Testing

Run the complete test suite with:

```
pytest -q
```

You can also check Python syntax with `python3 -m py_compile xray/*.py` and whitespace errors with `git diff --check`.

## Status

xray is under active development. The 0.8 series added error handling, exit codes and static analysis of Python. The 0.9 series adds a common model and analyzer registry, a command overview for shell scripts, ELF binaries and Python launchers, shell metrics and JSON export. Next planned: reading Perl and other scripts, more languages, and a visual graph viewer.

## Changelog

See `CHANGELOG.md` for what changed in each release.

## License

See the repository for licensing information.
