# xray

xray is a lightweight static-analysis tool for Python projects and for the commands installed on your system.

It builds a dependency graph of a Python project, reads the code inside it, and can follow a command such as `pytest` into the code it launches.

Think of it as a small X-ray machine for your codebase.

## What it can do

- **Dependency graph:** dependencies, dependents, trees, impact analysis, cycles, depth, reachability, paths and strongly connected components.
- **Commands:** follow a launcher into the installed code it runs, and show the tree of what a script or binary runs.
- **Static analysis of Python:** symbols, references, relationships, unused imports, unused symbols and complexity.
- **Architecture metrics:** a static call graph, module coupling and call coupling.

## Installation

From the project directory:

```
pip install -e .
```

## Usage

```
xray <target> [option]
```

The target is a file path or the name of a command found on your `PATH`. Without an option, xray prints the file type and a short summary of a Python file.

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
└── chain.py            tree of what a command runs
```

## Testing

Run the complete test suite with:

```
pytest -q
```

You can also check Python syntax with `python3 -m py_compile xray/*.py` and whitespace errors with `git diff --check`.

## Status

xray is under active development. The 0.8 series adds error handling, exit codes and static analysis of Python. The next planned step is a language-independent analysis model, then support for more languages and visualization.

## License

See the repository for licensing information.
