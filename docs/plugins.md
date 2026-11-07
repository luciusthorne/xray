# Plugins: teaching XRAY a new language

A plugin is an ordinary Python package that offers an analyzer under the
`xray.analyzers` entry point group. Once it is installed next to XRAY, files of
its language get the same views as XRAY's own script languages:

- `xray FILE --report` (definitions and imports), `--code`, `--code NAME`;
- `xray FILE --callgraph [NAME]` (calls to the file's own functions, found by
  name with the plugin's comment syntax blanked out);
- `xray inspect FILE`, `why`, `reach` and `--serve`, which follow its imports.

`xray plugins` lists what loaded and why anything failed. A plugin that fails
to import or is malformed is skipped; it never stops XRAY.

## The analyzer

```python
# toylang/__init__.py
import re
from pathlib import Path

from xray.analyzers import Analyzer
from xray.model import Edge
from xray.symbols import Symbol


class ToyAnalyzer(Analyzer):
    name = "toy"                 # unique among analyzers
    kinds = ("toy",)             # the kind XRAY reports for these files
    language = "Toy"             # shown in reports
    comments = ("//", ("/*", "*/"))  # line comment, block comment (or None)

    def claims(self, path):      # which files are yours (XRAY's own kinds always win)
        return Path(path).suffix == ".toy"

    def symbols(self, path):     # definitions, with end_line so --code can show them
        lines = Path(path).read_text().splitlines()
        out = []
        for number, line in enumerate(lines, 1):
            match = re.match(r"fn (\w+) \{", line)
            if match:
                end = next(n for n in range(number, len(lines) + 1) if lines[n - 1].strip() == "}")
                out.append(Symbol(match[1], "function", str(path), number, None, {"end_line": end}))
        return out

    def edges(self, path):       # what the file loads: "imports" edges, resolved to files when possible
        out = []
        for line in Path(path).read_text().splitlines():
            match = re.match(r"use (\w+)", line)
            if match:
                target = Path(path).parent / f"{match[1]}.toy"
                out.append(Edge(str(path), str(target) if target.exists() else None, "imports",
                                "resolved" if target.exists() else "unresolved", name=match[1]))
        return out
```

Symbol kinds are `function`, `method`, `class`, `module`, `variable`,
`interface` and `type`. Edges are the same records XRAY's own analyzers return.

## Registering it

```toml
# pyproject.toml of the plugin package
[project.entry-points."xray.analyzers"]
toy = "toylang:ToyAnalyzer"
```

The entry point may name an analyzer class, an instance, or a function that
returns one. Install the package into the same environment as XRAY (for a
`pipx`/`uv tool` install: `pipx inject xray-trust toylang` or
`uv tool install xray-trust --with toylang`).

## Rules

- Built-in analyzers win: a plugin cannot take over XRAY's own kinds (`elf`,
  `python`, `shell`, `perl`, `ruby`, `javascript`, `lua`, `typescript`, `c`,
  `lisp`).
- Plugins read files; they must not run the code they analyse.
- XRAY's own rule applies to what a plugin reports: evidence or it didn't
  happen. Edges and symbols should point at real lines.
