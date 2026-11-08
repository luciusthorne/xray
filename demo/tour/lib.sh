# Shared helpers for the tour scripts: a section title and a shown command.
say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
# run 'COMMAND LINE': print it as typed, then run it through the shell (pipes allowed).
run() { printf '\033[1m$ %s\033[0m\n' "$1"; eval "$1"; printf '\n'; }
