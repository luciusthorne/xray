# Changelog

## Unreleased

- **Qt signal-slot connections in `--callgraph FUNCTION`**: a signal's connected slots (`⇝`) and a slot's signals (`⇜`), with the function and line that connects them, read from each `connect()` call (signals are moc-generated functions; lambda slots are named by Qt's `QCallableObject` wrapper). Inferred; "maybe" when one connect sets up several functions. libQt6Widgets: 212 of 403 connects resolve to one signal and one slot.
- **Call graphs show library calls in `-fno-plt` builds** (Arch, Fedora and most distributions now): a call through a GOT slot (`call *0x…(%rip)`) is a call to the library function the slot is named after, not an unknown indirect call. xournalpp: 29,615 calls were hidden. `--callgraph` also uses the code map's function table, so stripped programs whose few exported symbols hid the debug file's table (`ls`: `main` showed no calls) get every caller. Operator names stay whole (`operator delete`, `Foo::operator()`).
- **C++ lambdas keep their own names**: `F::{lambda#2}` (nested: `F::{lambda#1}::{lambda#1}`) instead of folding into the function around them, so call graphs and `--code F` no longer mix a function with its lambdas; `std::function` invokers read `F::{lambda#1} (std::function)`.
- **C++ virtual calls in `--callgraph`** (x86-64): vtables read from the binary, the slot each indirect call uses (direct, tail jump, or loaded into a register first) and the method name on the call's source line give the methods a call can reach (`⇢`) and who reaches a method (`⇠`), labelled inferred. Virtual destructor calls (`delete`) and unresolved calls are counted. xournalpp: 609 of 933 vtable calls resolved.

## 1.1.0

Reading the code of Linux commands, in every language on a typical system:

- **Code map for compiled programs** (`--code`): every function with its readable name, source file and line, grouped into the program's own files, its dependencies and the standard library. `--code FILE` lists a file's functions and shows it; `--code FUNCTION` shows that function's source. C, C++ and Rust through the binary's DWARF or the debuginfod debug file for its build ID (one batched `addr2line`, `c++filt` for C++ and both Rust manglings); Rust dependencies from crates.io, the Rust standard library from the matching `rust-src`.
- **Go programs** read from the runtime's function table (`.gopclntab`) and build information, even stripped: names, files, lines and call graph; source from the Go module proxy and the Go repository at the exact versions; builds without `-trimpath` are normalised.
- **Programs without debug information** (Hyprland and other C++ programs): `--code NAME` finds the function in the upstream archive their Arch package was built from (named in `.SRCINFO`, checksum verified), labelled a by-name guess. Names-only programs get a namespace overview.
- **Debian and Ubuntu**: package ownership through dpkg (merged-`/usr` paths matched both ways) for `inspect`, `why`, `reach`, `scan`, `--report` and SBOM package URLs; source from sources.debian.org at the package's exact version, Debian's patches included.
- **Call graphs** (`--callgraph [FUNCTION]`): compiled programs (C, C++, Rust, Go) with files and lines, generic copies merged; shell scripts (functions, the commands each runs, who calls what); Perl, Ruby, JavaScript, TypeScript and Lua (calls found by name, comments and strings ignored).
- **Lisp** (Emacs Lisp, Scheme/Guile, Common Lisp, Clojure) with an exact S-expression reader: definitions, `--code`, exact call graphs, imports resolved through Emacs' and Guile's load paths, program starts.
- **Emacs package** (`editors/emacs/xray.el`): code map, function code, call graph, inspect, why, reach and serve in clickable `*xray*` buffers; `xray taint` findings through Flymake.
- **Plugins**: other packages add languages through the `xray.analyzers` entry point group; `xray plugins` lists what loaded and why anything failed. See docs/plugins.md.
- The graph page (`--serve`, `--html`), `--report` and `--browse` use the code map: readable function names with file and line, Show source for every language, source file lists. The page's layout cools to a stop, fits below the controls and has a Fit button.
- ELF dlopen metadata notes (`.note.dlopen`, used by systemd) become declared `dlopens` links: on an Arch desktop, programs reaching liblzma go from 411 to 909, most through `libsystemd.so.0`.
- C source and function names for stripped binaries through debuginfod; definitions found when braces appear in strings or comments.

Contracts and trust:

- **`[syscalls]`** (contract version 2): dangerous system calls the program shows no sign of needing (ptrace, kernel modules, mounts and namespaces, bpf, keyrings, ...) are denied; `contract enforce` blocks them with a seccomp filter (EPERM), `contract systemd` writes `SystemCallFilter=`, `check --trace` reports a run that makes one. Contracts without it stay version 1.
- **`xray contract kubernetes`**: a Pod and NetworkPolicy from a contract (no privilege escalation, read-only root, capabilities dropped, `[write]` as volumes, `[net]` as the only traffic, `[syscalls]` as a seccomp profile); validates with kubeconform.
- Cross-distribution study against Fedora (docs/crossdistro-study.md): the loader-hook rule stays at zero false positives across Arch/Debian and Arch/Fedora.

Project:

- Open source on GitHub; README leads with code reading; PyPI metadata; SECURITY.md and CONTRIBUTING.md; XRAY is stated to be Linux-only.
- Releases are built and published by `.github/workflows/release.yml` (PyPI trusted publishing, no token).
- CI runs once per pull request change (PRs test Python 3.10 and 3.15, `main` tests 3.10–3.15) and cancels superseded runs.

Earlier in this release:

- Add a VS Code extension (`editors/vscode`): taint diagnostics on save, the evidence graph in a panel, contract checks.
- Add `xray build --commands … / --contract …`: a minimal root filesystem (directory or tar) with only the files the evidence or contract names, the symlinks they are reached through, and `--check` runs inside it with bubblewrap.
- Add `xray query`: read-only SQL over the scan store or a capability log (`--log`), with `--schema`, `--examples` and `--json`.
- `xray taint` follows arguments by position across programs: a helper's `$2` / `sys.argv[2]` is tainted only when the caller passed input in that position, and the chain names the argument.
- `contract enforce`: read, exec and load entries with a glob (`/etc/tool/*.conf`) grant only the files that match when the program starts, instead of the whole directory.
- `drift` pairs files that move between version directories (perl 5.42 → 5.44 no longer reports `libperl.so` as a new file with new capabilities).
- docs/real-xz.md: Fedora Rawhide's xz builds as a second independent test — the loader-hook rule flags 5.6.0-2 and 5.6.1-1 and not 5.4.6-3 or the IFUNC-disabled 5.6.0-3; two of three distributions carried the payload, so cross-build comparison is "any disagreement", not a vote. demo/real-xz/run.sh fetches the Fedora builds too.
- Add `xray contract systemd`: a contract as systemd sandboxing settings (unit, drop-in, or `--run` with systemd-run), and `minimize --enforcer systemd`. Traced runs record execute-permission probes (`test -x`), which systemd's no-exec mounts change; `minimize` now compares with an unconfined run and warns when the full contract already changes a workload's result.
- Add `xray inspect CMD --sbom cyclonedx|spdx`: CycloneDX 1.6 and SPDX 2.3 bills of materials from the evidence graph, with hashes, package URLs and evidenced dependencies (validated with the official CycloneDX schema and spdx-tools).
- Add policy as code: `xray policy check POLICY` over drift, compare, feed, taint, scan or contract results (`allow|deny gain|taint|risk|breach PATTERN [in GLOB] [for PACKAGE]`, first match wins); the pacman hook can use a policy to decide what blocks.
- Add `xray attest`: contracts, profiles, reports and capability log heads as in-toto Statements, signed with an SSH key (`ssh-keygen -Y`, optionally also Sigstore cosign); `verify` checks the signature and re-hashes the subjects.
- `xray taint` reads compiled programs: functions where an input call (getenv, fgets, read, recv, …) is followed, directly or through called functions, by a code-execution call (system, popen, exec*, dlopen), with both source lines; labelled guessed (call order, not data flow).
- Add `xray explain FILE SYMBOL…` and `xray drift --explain`: every call to a newly imported function, with its function and source line (inline chains included), from the binary's debug information or a debuginfod server.
- `xray contract generate --workloads FILE` and `minimize --workloads FILE`: contracts from many workloads; an entry is required when any workload needs it.
- Fix: a traced run that lists a broad directory (`/`, `/usr`, `/etc`, the home directory, …) no longer adds it to `[read]`, which granted everything beneath it; the listing is recorded as a note.
- Add a GitHub Action (`action.yml`): runs an XRAY command, writes the job summary, fails on a non-zero exit; self-tested in CI. See docs/github-action.md.
- Add the pacman hook: `xray hook pacman` (run by pacman before installing upgrades) reports what each upgrade gains and re-checks contract pins, and in block mode stops upgrades with strong gains or broken contracts; `xray hook install` prints the install commands and uses a root-owned copy of XRAY.
- Cross-distribution study (docs/crossdistro-study.md): 241 Arch packages compared with Debian's builds of the same releases. Constructors are now a weak difference in `xray compare` (build flags change them in 7% of packages).
- Add the live Arch capability feed: `xray feed update` (every package update since the last run, signature- and hash-checked, profiled into the log and compared with the version before it), `xray feed report` (text or HTML) and `xray feed timer` (a systemd user timer).
- Add `xray compare A B`: two builds of the same release compared file by file (paired by name), listing what only one build can do, with strong differences (call classes, loader hooks or dependence on the dynamic loader, IFUNCs, constructors, setuid) separated from weak ones. Add `tools/crossdistro_study.py` for Arch-versus-Debian studies.
- Detect the xz backdoor's loader hook: a library outside glibc that links the dynamic loader and has IFUNC resolvers. `drift` reports it as a gain and `inspect`/`scan` list it under "Worth a look". Checked on Debian's real backdoored liblzma5 5.6.0/5.6.1 (flagged), every clean liblzma build around them and Arch's builds of the same versions (not flagged), and 1,019 archives of the top 500 Arch packages and a full desktop install (no false positives). See docs/real-xz.md and demo/real-xz/run.sh.
- `drift` and the capability log read Debian `.deb` packages.
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
