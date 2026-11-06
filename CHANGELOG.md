# Changelog

## Unreleased

- Add `xray inspect CMD --html`: the evidence graph as a self-contained interactive page with edges styled by basis, per-link evidence, the strongest path to any node, blind spots and findings; `#node=NAME` deep links.
- Add `xray taint COMMAND` and `xray taint --scan`: untrusted input (arguments, stdin, network downloads, web request data, environment) followed to code-running sinks in shell and Python, through variables, arrays, loops, functions and returns, and across programs that pass tainted arguments or exported variables to each other. Severity follows trust boundaries (network or setuid: high; arguments into eval or a shell: medium).
- The shell parser records which function each command belongs to, every assignment site, and for/select loops.
- Add capability profiles (`xray/profile.py`) and `xray drift OLD NEW` for files, directories, package archives and installed packages: imported call classes, libraries, search paths, IFUNC resolvers, constructors, setuid bits and script commands, with rebuilt or renamed libraries paired instead of reported as new.
- Add `xray whatif upgrade ARCHIVE` (drift from the installed version, plus the scanned programs that reach each file that gained a capability) and `xray whatif remove PACKAGE`.
- Add the capability transparency log: `xray log add` (archives or `--from-cache`), `verify` (hash chain), `history NAME` and `gains`.
- Contract `[exec]` and `[load]` entries pin what each ELF file is able to do (`caps=`, `ifuncs=`, `ctors=`); `xray contract check` reports a file that gained a capability under the same name.
- Add `demo/xz-style`, a harmless re-enactment of the xz backdoor pattern.
- Add capability contracts ([spec](docs/contract-spec.md)): `xray contract generate` (from the evidence graph, plus a strace-observed run with `--trace`), `check` (breaches with proof chains; `--trace` checks a real run; `--strict` flags a changed program), `enforce` (Landlock file and TCP rules, unprivileged, plus a private network namespace when the contract allows no network) and `minimize` (delta debugging over entries until every remaining one is required by the workload).
- `#!/usr/bin/env NAME` scripts now link to `env` itself (declared) as well as the interpreter it finds on PATH.
- Add the evidence graph and two verbs. `xray inspect <command>` shows what a command reaches (commands, sourced files, Python and Perl imports, interpreters, shared libraries, owning packages) with the proof for every link — method, file and line, and a basis of observed, declared, inferred or guessed — plus its blind spots; `--trace` merges a real run and lists what static reading missed. `xray why <command> <target>` prints the proof chains to a file, command, library or package.
- The shell reader no longer reports a command named `_` when a command substitution is itself run (`$(printf "$cmd")`); it counts as a command built at runtime.
- Python import resolution keeps the line of each import; package ownership can be looked up for many files in one pacman call.
- Read shell scripts with a full parser (`xray/shparse.py`) instead of line patterns. `case` patterns and `getopts` letters are no longer reported as commands; multi-line `$(...)`, arrays, `[[ ]]`, `(( ))`, `for ((...))` and every redirection form are understood; unquoted here-document substitutions, `trap` strings and `sh -c`/`su -c` strings are read as code; `command -v` is a lookup, not a run. Every use keeps its line number.
- Resolve commands run through a variable the script only ever sets to fixed values (`CMD=(foot -e)` … `"${CMD[@]}"`), labelled guessed.
- Resolve shared libraries in the dynamic loader's order (`DT_RPATH` with inheritance, `LD_LIBRARY_PATH` except for setuid programs, `DT_RUNPATH`, ldconfig cache entries for the binary's word size, default directories; `$ORIGIN`, `$LIB`, `$PLATFORM`, `-z nodefaultlib`). Each link names the step that found the library. Empty, relative, world-writable or foreign-owned search path entries are reported under "Worth a look".
- Follow commands Python files start (`subprocess`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `posix_spawn`, `asyncio`, `pty`), through import aliases; shell strings are parsed.
- The evidence graph follows Ruby, JavaScript, TypeScript and Lua imports, C `#include`s, and literal command starts in Ruby, Node and Lua.
- Add `xray inspect --tree`, the evidence graph as a tree with each link's basis and line; it supersedes `--chain` and `--launch`.
- Add `xray scan`, which reads every command on PATH into a cached evidence store keyed by file signature, SHA-256 and machine state, and `xray reach <target>`, which lists the programs that reach a file, library, command or package with a proof chain for each.

## 1.0.0

- Publish as `xray-trust` on PyPI (the `xray` name is taken); the command is still `xray`.
- License the project under Apache-2.0.

- Add `--toolchain`: the language that built an ELF binary (Go module, dependencies and build settings; Rust compiler and crates; C++, Fortran, D, Haskell, Swift, Objective-C runtimes; C, inferred when `.comment` is stripped; PyInstaller) and the compilers in `.comment`. `--report` and `--inspect` show the language on their Identity line.
- Add a trailing `--json` modifier that prints any text query as a versioned JSON document (title, sections, fields, items, lines).
- Add `--browse`, a terminal menu over the overview, functions and their code, calls, chain, toolchain, and uses views.
- `--code <name>` shows the whole definition for JavaScript, TypeScript, Ruby, Lua, C, shell, and Perl, using parser end lines or the matching closing brace, instead of a 60-line excerpt that could run into the next definition.
- The shell reader follows commands run through `sudo`, `doas`, `env`, `nice`, `ionice`, `stdbuf`, `timeout`, `xargs`, and `find -exec`; reads process substitutions; and reads literal `eval` strings as shell code.
- RPM source lookup prefers the binary's own source file when several files define the same function (`ls --code main` opens `src/ls.c`).
- `--disasm-function` falls back to the symbol's exact range when rizin's `pdf` refuses a function, disables colour codes, and reports rizin's error text.
- Report a missing Neovim Tree-sitter grammar as "parser unavailable" (Neovim 0.12 returns no parser instead of raising), and gate parser tests on the installed grammar.
- Verified on Fedora 45 (Python 3.15) with real rpm/dnf source retrieval, strace, rizin, and Neovim, and on Arch with Python 3.10–3.14.

- Make a bare `xray` invocation inspect XRAY's own CLI, and show relevant follow-up commands in every default command overview.
- Build project dependency graphs through the analyzer registry for supported languages, including resolved in-project imports and sourced files.
- Preserve and report external and unresolved project dependencies separately from file-to-file graph edges.
- Add `--changes [<base-ref>]` to list Git changes and current in-project dependents.
- Make `--code` show bounded `objdump` disassembly for stripped ELF commands when source/debug data is unavailable, and make reports state the package-manager-specific source limit.
- Read function tables from standard ELF symbols when `.gnu_debugdata` is absent, disassemble named symbols by their exact address range, and support same-line C function definitions in local source lookup.
- Use configured elfutils debuginfod servers to retrieve DWARF and source files for named ELF functions, with bounded lookups and existing local/RPM/disassembly fallbacks.
- Let `--code` list function names recovered from DWARF so users can discover named source queries for stripped binaries.
- Add commands to list, remove, and clear downloaded source-package caches without touching parser-result caches.
- Stage source-package extraction, serialize cache use and mutation between XRAY processes, and support optional least-recently-used size pruning through `XRAY_SOURCE_CACHE_MAX_MIB`.
- Make the `pod2man` integration test discover the executable through `PATH`.

- Do not show unresolved ELF library edges as resolved file paths in `--calls`.
- Include the `test_programs` fixtures in source archives so the complete suite runs from the sdist.
- Align regression expectations and CLI documentation with the expanded language analyzers, symbol kinds, Python summaries, and JSON contracts.
- Add an optional test dependency group and run the full regression suite across the supported Python matrix in CI.
- Read package metadata version from `xray.__version__` to keep wheel metadata and CLI version aligned.
- Include the changelog in source distributions alongside the README.
- Run the focused suite and clean-install smoke checks on Python 3.10–3.14 in GitHub Actions.
- Exercise live loopback source-viewer script and binary routes, function/file allowlisting, and Host validation in the tests.
- Cover the 400-line source-file cap and reject paths that traverse or symlink outside the source root.
- Test ELF symbol-table parsing, call attribution, and `.gnu_debugdata` extraction from a real compiled fixture.
- Verify `objdump` call attribution against a real compiled ELF with `.gnu_debugdata`.
- Check that Rizin receives only validated function addresses and reports missing-tool guidance.
- Include focused tests in source archives while excluding workspace-only notes, scratch files, caches, and CI configuration.
- Ignore Neovim log lines after Tree-sitter JSON responses so Lua, TypeScript, and C analysis can use valid parser output.
- Report pacman package ownership and clarify that source package retrieval currently requires RPM/DNF.
- Preserve pacman ownership details when named ELF source lookup cannot fetch RPM source metadata.
- Let `--code <name>` show Python functions, async functions, classes, and qualified methods using AST source ranges without executing the target.
- Escape backticks safely in Markdown report paths and suggested commands.
- Reject non-loopback HTTP `Host` headers in the local source viewer.
- Keep script-like graph labels escaped in the self-contained HTML data block.
- Include the `max_functions` bound in graph JSON metadata and test its truncation behavior.
- Report missing Node.js, Ruby, and Neovim parser dependencies through the CLI's stable analysis-error path.
- Expand coverage for report and inspect formats, source caches, JSON contracts, graph limits, and static-analysis safety.

## 0.9.65
- Add `--inspect [--md]`, combining command identity, overview, and source information in one inspection.
