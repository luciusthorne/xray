xray

xray is a lightweight Python project dependency analyzer.

It scans Python projects, builds a dependency graph, and lets you inspect how files are connected.

Think of it as a small X-ray machine for your codebase.

Features

xray can:

Analyze Python files

Detect imports and dependencies

Build project dependency graphs

Find dependency hotspots

Detect circular dependencies

Show dependency trees

Analyze file impact

Show impact chains

Calculate dependency depth

Find reachable dependencies

Find reverse-reachable dependents

Find paths between files

Find strongly connected components

Show project statistics

Installation

From the project directory:

pip install -e .

Basic Usage

Run xray against a Python file:

xray test_programs/cycle_a.py


You can add a query to inspect different parts of the dependency graph.

You can also run the CLI as a Python module:

python -m xray.cli test_programs/cycle_a.py

Commands
--deps

Show what the selected file depends on.

xray test_programs/cycle_a.py --deps


Useful for answering:

What does this file use?

--dependents

Show which files depend on the selected file.

xray test_programs/cycle_a.py --dependents


Useful for understanding which files may be affected by changes to the selected file.

--tree

Show the dependency structure as a tree.

xray test_programs/cycle_a.py --tree


Example:

cycle_a.py
├── cycle_b.py
│   └── cycle_c.py
└── ...

--impact

Analyze the impact of a file.

xray test_programs/cycle_a.py --impact


The report separates directly affected files from indirectly affected files and can also show impact chains.

--cycles

Find circular dependencies.

xray test_programs/cycle_a.py --cycles


Example:

cycle_a.py → cycle_b.py → cycle_c.py → cycle_a.py

--depth

Calculate dependency depth.

xray test_programs/cycle_a.py --depth


The result shows the maximum dependency depth starting from the selected file.

--project

Show project statistics.

xray test_programs/cycle_a.py --project


The project report includes:

Python file count

Dependency edge count

Leaf files

Circular dependencies

Dependency hotspots

--components

Show strongly connected components.

xray test_programs/cycle_a.py --components


This groups files that are mutually reachable through the dependency graph.

It is particularly useful when investigating circular dependencies.

--reachable

Show everything reachable from the selected file.

xray test_programs/cycle_a.py --reachable


In other words:

Starting here, what can I eventually reach?

--reverse-reachable

Show everything that can reach the selected file.

xray test_programs/cycle_a.py --reverse-reachable


This answers:

What files can eventually depend on this?

--path

Find a dependency path from the selected file to another file.

xray test_programs/cycle_a.py --path test_programs/cycle_c.py


Example:

cycle_a.py → cycle_b.py → cycle_c.py


xray finds the shortest dependency path. If no path exists, it reports:

No path found

Help

To see the available commands:

xray --help


You can also use:

xray -h


Or:

python -m xray.cli --help

How It Works

At its core, xray builds a directed dependency graph.

A dependency such as:

a.py → b.py


means that a.py depends on b.py.

Once the project has been converted into a graph, xray can perform different analyses on that graph.

This makes features such as:

cycle detection

reachability analysis

path finding

impact analysis

dependency depth

strongly connected component analysis

possible on top of the same graph representation.

Project Structure

The main parts of xray are separated by responsibility:

xray/
├── analyze.py
├── classify.py
├── cli.py
├── dependencies.py
├── discover.py
├── graph.py
└── identify.py


The graph engine lives in:

xray/graph.py


The command-line interface lives in:

xray/cli.py


Python source analysis is handled by:

xray/analyze.py

Testing

Run the complete test suite with:

pytest -q


The current test suite covers Python analysis, dependency graph behavior, graph algorithms, import resolution, cycle detection, reachability, path finding, and CLI functionality.

The release baseline currently passes:

64 passed


You can also check Python syntax with:

python3 -m py_compile xray/*.py


And check for whitespace errors with:

git diff --check

Why xray?

Large projects can make dependency relationships difficult to see.

A file might depend on another file, which depends on another, eventually producing a graph that is much harder to understand than the source code itself.

xray makes that graph easier to inspect.

Instead of guessing how files are connected, use xray to see those relationships directly.

Status

xray is an actively developed lightweight dependency-analysis tool.

The project currently focuses on Python projects and graph-based dependency analysis.

The 0.7.0 release focuses on expanding graph analysis and exposing those capabilities through the command-line interface.

More analysis features can be built on top of the dependency graph as the project grows.

License

See the repository for licensing information.
