# XRAY for VS Code

Uses the `xray` command (install `xray-trust`) to show, in the editor:

- **Untrusted input reaching code** in shell and Python files: `xray taint`
  findings as diagnostics on save (network input reaching `eval` is an error;
  arguments reaching a shell are warnings). Findings in scripts this file calls
  appear on the line that passes the input on.
- **The evidence graph** of the current file: *XRAY: Show the evidence graph of
  this file* opens `xray inspect --html` beside the editor.
- **Contract checks**: *XRAY: Check a capability contract* runs
  `xray contract check` on a `.contract` file.

Settings: `xray.path`, `xray.taintOnSave`, `xray.showLow`.
