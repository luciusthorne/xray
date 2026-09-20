xray

xray is a lightweight Python project dependency analyzer.

It looks at your Python project, finds how files depend on each other, and gives you a clear view of what is connected to what.

Think of it as a small X-ray machine for your codebase.
What can xray do?

xray can:

    Analyze Python files

    Detect imports and dependencies

    Build dependency graphs

    Find dependency hotspots

    Detect circular dependencies

    Show dependency trees

    Analyze the impact of a file

    Show dependency chains

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

python -m xray.cli test_programs/cycle_a.py

You can then add a query to see different parts of the dependency graph.
Commands
--deps

Show what the selected file depends on.

python -m xray.cli test_programs/cycle_a.py --deps

Useful when you want to answer:

    "What does this file use?"

--dependents

Show which files depend on the selected file.

python -m xray.cli test_programs/cycle_a.py --dependents

This is useful for finding out:

    "What would be affected if I changed this file?"

--tree

Show the dependency structure as a tree.

python -m xray.cli test_programs/cycle_a.py --tree

This makes nested dependencies easier to understand at a glance.
--impact

Analyze the impact of a file.

python -m xray.cli test_programs/cycle_a.py --impact

xray separates directly affected files from indirectly affected files and can also show the dependency chains involved.
--cycles

Find circular dependencies.

python -m xray.cli test_programs/cycle_a.py --cycles

Example:

cycle_a.py → cycle_b.py → cycle_c.py → cycle_a.py

Circular dependencies can be difficult to notice when looking at individual files. xray makes them visible.
--depth

Calculate how deep the dependency chain goes.

python -m xray.cli test_programs/cycle_a.py --depth

The result shows the maximum dependency depth starting from the selected file.
--project

Show statistics about the project.

python -m xray.cli test_programs/cycle_a.py --project

The project report includes information such as:

    Python file count

    Dependency edge count

    Leaf files

    Circular dependencies

    Dependency hotspots

--components

Show strongly connected components.

python -m xray.cli test_programs/cycle_a.py --components

This groups files that are strongly connected through the dependency graph.

It is especially useful when investigating complicated dependency cycles.
--reachable

Show everything reachable from the selected file.

python -m xray.cli test_programs/cycle_a.py --reachable

In other words:

    "Starting here, what can I eventually reach?"

--reverse-reachable

Show everything that can reach the selected file.

python -m xray.cli test_programs/cycle_a.py --reverse-reachable

This answers the opposite question:

    "What can eventually depend on this?"

--path

Find a dependency path between two files.

python -m xray.cli test_programs/cycle_a.py --path test_programs/cycle_c.py

Example:

cycle_a.py → cycle_b.py → cycle_c.py

If no path exists, xray reports:

No path found

Help

To see the available commands:

python -m xray.cli --help

You can also use:

python -m xray.cli -h

How it works

At its core, xray builds a directed graph.

A dependency such as:

a.py → b.py

means that a.py depends on b.py.

Once the project has been converted into a graph, xray can perform different analyses on that graph.

That makes features like cycles, reachability, paths, impact analysis, and dependency depth possible.
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

The project currently contains tests covering the analyzer, dependency graph, and CLI behavior.

A passing test run looks like:

41 passed

Why xray?

Large projects can make dependency relationships difficult to see.

A file might depend on another file.

That file might depend on another.

Eventually, you can end up with a graph that is much harder to understand than the source code itself.

xray is meant to make that graph easier to inspect.

Instead of guessing how your files are connected, use xray to see it.
Status

xray is an actively developed lightweight dependency-analysis tool.

The project currently focuses on Python projects and graph-based dependency analysis.

More analysis features can be built on top of the dependency graph as the project grows.
License

See the repository for licensing information.
