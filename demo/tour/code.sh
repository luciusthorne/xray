#!/usr/bin/env bash
# Tour 3: read the code of installed commands: C, Rust, Go and shell.
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

say "C: the source of ls's main(), fetched for this exact build"
run 'xray ls --code main | head -24'

say "Rust: ripgrep's source files, then one function"
run 'xray rg --code | sed -n 6,16p'
run 'xray rg --code rg::main | sed -n 6,16p'

say "Rust: what a function calls, each with file:line"
run 'xray rg --callgraph rg::search | sed -n 6,14p'

say "Go: gh's main, from the Go module proxy at the exact version"
run 'xray gh --code main.main | sed -n 6,20p'

say "Shell: xdg-mime's functions and where each is called"
run 'xray xdg-mime --callgraph | sed -n 6,16p'
