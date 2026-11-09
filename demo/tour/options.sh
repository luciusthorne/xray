#!/usr/bin/env bash
# Tour 2: the main options, each on a real installed command.
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

say "Which package owns a command"
run 'xray jq --package'

say "Everything a command reaches, with the proof for each link"
run 'xray inspect jq'

say "Why one thing reaches another: the proof chain"
run 'xray why curl libssl | head -12'

say "The tree of what a script runs"
run 'xray xdg-open --chain | head -14'
