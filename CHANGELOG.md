# Changelog

## Unreleased

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
