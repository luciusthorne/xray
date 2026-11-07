# xray.el

Read the code of Linux commands from Emacs. A front end for the `xray`
command, with no dependencies beyond Emacs 27.1.

## Install

```elisp
(add-to-list 'load-path "/path/to/xray/editors/emacs")
(require 'xray)
(global-set-key (kbd "C-c x") #'xray)          ; menu of every view

;; taint findings while editing scripts
(add-hook 'sh-mode-hook #'xray-flymake-setup)
(add-hook 'python-mode-hook #'xray-flymake-setup)
```

With `use-package`:

```elisp
(use-package xray
  :load-path "/path/to/xray/editors/emacs"
  :bind ("C-c x" . xray)
  :hook ((sh-mode python-mode) . xray-flymake-setup))
```

`xray-program` names the executable (default `xray`).

## Commands

| Command | Shows |
| --- | --- |
| `xray` | a menu of everything below |
| `xray-code` | a command's files and functions (the code map), or one function's or file's code |
| `xray-code-at-point` | the code of the function named at point, read from this buffer's file |
| `xray-callgraph` | which function calls which, or one function in both directions |
| `xray-report` | the overview of a command |
| `xray-inspect` | what a command reaches, with the proof for every link |
| `xray-why` | the proof chains from a command to a file, library or package |
| `xray-reach` | which scanned programs reach a file or library |
| `xray-serve` | the interactive page in a browser |

## In an `*xray*` buffer

| Key | Does |
| --- | --- |
| `RET` on a function name | that function's code |
| `RET` on a source file | the file's functions, then its text |
| `RET` on `PATH:LINE` | visits the file at that line (when it is on this machine) |
| `c` | the call graph of the name at point |
| `g` | runs the command again |
| `TAB` / `S-TAB` | next / previous button |

Works for every language XRAY reads: C, C++, Rust and Go programs, and
shell, Python, Perl, Ruby, JavaScript, TypeScript, Lua and Lisp files
(Emacs Lisp included: `M-x xray-callgraph RET ~/.config/emacs/init.el`).

## Tests

```sh
emacs --batch -Q -L editors/emacs -l xray-tests.el -f ert-run-tests-batch-and-exit
```

`XRAY_TEST_PROGRAM=/path/to/xray` also runs the end-to-end test.
