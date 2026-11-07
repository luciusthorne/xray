# Contributing

Thanks for helping. Bug reports, new languages, better coverage and fixes are
all welcome.

## Setup

```sh
git clone https://github.com/luciusthorne/xray
cd xray
python -m pip install -e '.[test]'        # or: uv run --with pytest --with-editable . python -m pytest
python -m pytest -q
ruff check xray tests
```

Some tests need system tools (`readelf`, `objdump`, `strace`, `cc`, `go`,
`emacs`, `bwrap`, Neovim's Tree-sitter parsers) and skip without them. CI runs
the full suite on Python 3.10–3.15 and a Fedora container.

## Rules the code follows

- **Evidence or it didn't happen.** Every link XRAY reports carries how it was
  found (observed, declared, inferred, guessed) and where (file and line). A
  guess is labelled as a guess.
- **Never claim safe.** Reports list their blind spots; a missing link is not
  proof that something cannot happen.
- **Read, don't run.** Analysis reads files. Only options that say so
  (`--trace`, `contract enforce`, `minimize`, `build --check`) run a program.
- **Downloads are checked and contained.** Fetch only from the source shown,
  verify checksums when one exists, extract only the files needed, and never
  follow links or `../` out of the cache.
- **Test on real programs.** A feature for a language or format comes with a
  test on a real file of that kind (built in the test when possible) and is
  tried on real installed programs before it is merged.

## Pull requests

- One change per pull request, with tests.
- Describe what changed, how you checked it, and what it does not cover.
- `python -m pytest -q` and `ruff check xray tests` pass.
- New modules go in the project structure list in `README.md` (a test checks).

## Adding a language

Most languages fit one of three places:

- **Compiled with DWARF line information** (C, C++, Rust, Zig, ...):
  `xray/codemap.py` already maps functions to files and lines; a new language
  usually needs name demangling and a test binary.
- **Scripts**: an analyzer in `xray/analyzers.py`'s registry that returns
  symbols with `end_line`, plus import edges; `xray/scriptgraph.py` gives the
  call graph.
- **Its own format** (Go's `.gopclntab`, Lisp's S-expressions): a reader of
  its own, like `xray/gocode.py` or `xray/lisp.py`.
