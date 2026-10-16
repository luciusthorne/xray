# Changelog

Each entry is one released version, newest first. Versions 0.8.5 to 0.9.29
were reconstructed from the commit history. Version 0.8.4 has no tag: its
work shipped as 0.8.5.

## 0.9.59
- `--path` and `--project` work on shell, ELF and Perl commands. `--path`
  takes a command name, a library name or a path.

## 0.9.58
- Perl scripts and modules work in `--calls`, `--chain` and the overview, and
  `.pm` and `.pl` files are recognized as Perl.

## 0.9.57
- Remove a duplicated `cached_source_files` definition, which the 0.9.56 repeat test found.

## 0.9.56
- Remove a duplicated `disasm_result` definition, and test that no module repeats a top-level name.

## 0.9.55
- The graph page has a light theme toggle (remembered) and a draggable side panel.

## 0.9.54
- The graph page side panel has tabs (Overview, Edges, Code) for a selected
  node. Cycles, path and impact results still fill the whole panel.

## 0.9.53
- `--serve` shows source, disassembly and script text in a code viewer:
  syntax highlighting for C, shell, Perl and Python, and a line-number
  gutter that is not copied with the text.

## 0.9.52
- `--serve` works on scripts too: a command box with Back and Forward, Open this
  command on any file node, and Show text for scripts. Only ELF, shell, Perl and
  Python files are served.

## 0.9.51
- Add `--report [--md]`: identity, package, overview and cached source files of a
  command in one report, as text or Markdown.

## 0.9.50
- `--help` groups the options by topic: code, binaries, scripts, graph, Python, export.

## 0.9.49
- Add `--code`: one option to read the code of any command, with `--asm` for
  disassembly next to a function's source.

## 0.9.48
- `--source` without a name lists the source files of a binary, and with a
  file name prints that file. In `--serve`, clicking the binary lists its files.

## 0.9.47
- Add `--serve`: a local page for an ELF binary where clicking a function
  loads its C source and annotated disassembly.

## 0.9.46
- Add `--source <function>`: the C source of a function of an installed
  binary, from its source package (downloaded once into the cache).

## 0.9.45
- `--tree`, `--deps`, `--dependents`, `--impact`, `--cycles`, `--depth`,
  `--components`, `--reachable` and `--reverse-reachable` work on shell
  scripts, ELF binaries and Perl scripts, using the graph of what a
  command runs, sources, imports or links to. `--path` and `--project`
  still need a Python project.

## 0.9.44
- Add a Perl reader and `PerlAnalyzer`: `use` and `require` become import
  edges resolved under perl's include paths, and `sub` definitions become
  symbols. `--json` picks them up. POD, pragmas and version numbers are
  skipped. Modules loaded through `use parent` or built strings, and
  `system` or `exec` calls, are not read yet.

## 0.9.43
- Add `--disasm-function <name>`: one function of an ELF binary as
  annotated disassembly through rizin. Names are checked against the
  function table first and rizin is given the address.

## 0.9.42
- List every module in the README project structure, and test that the
  list matches the files in `xray/`.

## 0.9.41
- `--json` adds a note with the number of shell commands run through
  variables or eval, so scripts reading the JSON can see the gap.

## 0.9.40
- Document that the variable-command count includes boolean tests such as
  `if $flag`, and replace a test that asserted nothing with tests of the
  real behavior. No code change: on /usr/bin/zgrep all 15 counted
  segments were checked by hand.

## 0.9.39
- The count of shell commands run through variables or eval only counts
  real variable references and eval, not text that merely starts with a
  dollar sign, such as the end of a multi-line sed script.

## 0.9.38
- Shell scripts: `--calls` and the overview count commands run through
  variables or `eval`, which cannot be resolved statically, so the gap
  is visible instead of silent.

## 0.9.37
- `--graph-json` and `--html` add the functions of an ELF binary and the
  calls between them (from `--disasm`), with imports as separate nodes.
  Up to 300 functions; `truncated` says when that limit cut the graph.

## 0.9.36
- `--uses` attributes names that libc does not provide to the needed
  library that exports them (with its package), so only names no library
  exports stay under other. The default overview is unchanged.

## 0.9.35
- `--uses` recognizes more names: library families by prefix (curl, acl,
  SSL, compression, xml) and the C type checks, `stdout`, `dirfd` and
  similar names. On `sed` and `curl` far fewer imports fall under "other".

## 0.9.34
- Add `--uses`: the imports of an ELF binary grouped by purpose. The ELF
  overview gets a one-line `Uses:` summary when any name is recognized.

## 0.9.33
- Fix `--disasm` on stripped binaries. 0.9.32 filed calls under the nearest
  exported symbol (for example `error@@Base`), so callers and callees were
  wrong. Calls are now matched by address against the function table in
  `.gnu_debugdata`; calls that cannot be matched are counted, not guessed.

## 0.9.32
- Add `--disasm`: direct calls between the functions of an ELF binary,
  read from `objdump -d`. Indirect calls are counted, not resolved.

## 0.9.31
- Read the function names that stripped binaries keep in
  `.gnu_debugdata`: the ELF overview lists them, and
  `ELFAnalyzer.symbols` returns them (line is always 1).

## 0.9.30
- Add this changelog, and a test that requires an entry for every release.

## 0.9.29
- Graph page: each node's panel shows how many files it reaches, how many
  would be affected if it changed, and whether it sits in a cycle.

## 0.9.28
- Graph page: "Show impact" colors the files affected by the selected node.

## 0.9.27
- Graph page: highlight cycles, and shift-click a second node to trace the
  shortest path.

## 0.9.26
- Graph page: search box and kind filters (python, shell, elf, library).

## 0.9.25
- Add `--html`: one self-contained, offline page that draws the graph, with
  zoom, pan, dragging and click-to-inspect.

## 0.9.24
- Add `--graph-json`: the whole graph of a command (nodes, edges with names,
  metadata) as JSON.

## 0.9.23
- Fix a crash when the `file` command is not available.

## 0.9.22
- Add `--trace`: runs the command under strace and lists the programs it
  executes and the files it opens.

## 0.9.21
- ELF overview shows each library with its owning package, and the import
  count instead of a long list.

## 0.9.20
- Overview of shell scripts ends with a compact chain.

## 0.9.19
- Default view shows the package that owns the file.

## 0.9.18
- Add `--package`.

## 0.9.17
- Find the installed package that owns a file (rpm).

## 0.9.16
- `--calls` reads shell scripts through `ShellAnalyzer`.

## 0.9.15
- `ShellAnalyzer.symbols` returns shell functions with line numbers.

## 0.9.14
- Move command lookup into `xray/locate.py`.

## 0.9.13
- `--chain` reads ELF libraries through `ELFAnalyzer`.

## 0.9.12
- `--chain` reads shell commands through `ShellAnalyzer`.

## 0.9.11
- `Edge` gets a `name`, filled by the shell and ELF analyzers.

## 0.9.10
- Document the 0.9 series, and test that every `--help` option is in the
  README.

## 0.9.9
- `--json` adds notes when shell commands are not visible.

## 0.9.8
- Fix metrics for shell functions whose body is a subshell.

## 0.9.7
- Add `--json`: symbols and edges of one file.

## 0.9.6
- Add `--shell-metrics`.

## 0.9.5
- Add `ShellAnalyzer` and `ELFAnalyzer`.

## 0.9.4
- Explain when a shell script shows no visible commands.

## 0.9.3
- Default view shows what a command runs.

## 0.9.2
- Add `PythonAnalyzer`.

## 0.9.1
- Add the analyzer interface and registry.

## 0.9.0
- Add common model types (`Edge`, `FileInfo`).

## 0.8.34
- Resolve calls through modules imported with `from pkg import module`.

## 0.8.33
- Rewrite the README, add `--version`, and document exit codes.

## 0.8.32
- Resolve calls through module attributes (`utils.calculate()`).

## 0.8.31
- Expose the call graph, unused symbols and coupling in the CLI.

## 0.8.30
- Expose symbols, references, relationships, unused imports and complexity in
  the CLI.

## 0.8.29
- `--chain` reports when the depth limit cut the tree.

## 0.8.28
- Refactor: every query moved out of `run()` into its own function.

## 0.8.27
- Fix `python -m xray` to return the exit code.

## 0.8.26
- `--chain` follows Python launchers into installed code.

## 0.8.25
- Add `--chain`: the tree of what a command runs.

## 0.8.24
- `--calls` shows ELF libraries and imports.

## 0.8.23
- Add the ELF reader for libraries and symbols.

## 0.8.22
- Add `--calls` for shell scripts.

## 0.8.21
- Fix shell case patterns with spaces around pipes.

## 0.8.20
- Add the static shell script reader.

## 0.8.19
- Report truncation and add `--launch-limit`.

## 0.8.18
- Add the `--launch-depth` option that 0.8.17 was missing.

## 0.8.17
- Follow relative imports in launchers.

## 0.8.16
- Add `--launch`.

## 0.8.15
- Build a graph from a command into its installed code.

## 0.8.14
- Classify commands and follow launchers into installed packages.
- Analyze extensionless Python commands.

## 0.8.13
- Add coupling metrics.

## 0.8.12
- Add complexity metrics.

## 0.8.11
- Find unused symbols.

## 0.8.10
- Find unused imports.

## 0.8.9
- Add the static call graph.

## 0.8.8
- Find class and function relationships.
- Skip unparsable sibling files when building the graph, and always analyze
  the target file strictly.

## 0.8.7
- Resolve references to imported definitions.

## 0.8.6
- Extract Python symbols.

## 0.8.5
- Add the symbol model.

## 0.8.3
- Reject unknown leading options. Cover non-Python targets and empty graphs.

## 0.8.2
- Reject extra CLI arguments.

## 0.8.1
- Structured CLI error handling, exit codes, and clean analysis and file
  errors.

## 0.7.0
- Graph analysis exposed through the command line: dependencies, dependents,
  trees, impact, cycles, depth, project statistics, components,
  reachability and paths.
