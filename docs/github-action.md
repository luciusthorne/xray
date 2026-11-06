# XRAY GitHub Action

Run XRAY in CI with one step. The action installs XRAY, runs the command you
give it, prints the output, adds it to the job summary, and fails the step when
XRAY exits non-zero.

```yaml
- uses: luciusthorne/xray@v1
  with:
    command: taint scripts/deploy.sh
```

| Input | Default | |
| --- | --- | --- |
| `command` | required | the command line after `xray`, run by bash |
| `python-version` | `3.12` | |
| `working-directory` | `.` | |

Output: `exit-code`.

## Recipes

**Fail a pull request when a build gains capabilities**: build the old and
new versions into two directories (or download two release archives), then:

```yaml
- uses: luciusthorne/xray@v1
  with:
    command: drift build-main/ build-pr/ --fail-on-gain
```

**Keep a program inside its contract**: commit `app.contract`, then:

```yaml
- uses: luciusthorne/xray@v1
  with:
    command: contract check app.contract --strict
```

**Catch untrusted input reaching eval or a shell**: `taint` exits 1 on a
high-severity finding:

```yaml
- uses: luciusthorne/xray@v1
  with:
    command: taint install.sh
```

**Two builds of the same release** (for packagers):

```yaml
- uses: luciusthorne/xray@v1
  with:
    command: compare ours.pkg.tar.zst upstream.deb --fail-on-strong
```

To report without failing the job, add `continue-on-error: true` and read
`steps.<id>.outputs.exit-code`.

The `command` input is passed to bash with `eval`, like a `run:` step: write
it in the workflow, never build it from pull request titles, branch names or
other text an outside contributor controls.
