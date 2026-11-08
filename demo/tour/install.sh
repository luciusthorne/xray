#!/usr/bin/env bash
# Tour 1: install XRAY with pipx from a fresh clone, then run it.
# Runs with a temporary HOME and a plain PATH, so an xray you already have is neither
# used nor touched. XRAY_TOUR_SOURCE overrides what is installed (default: ./xray).
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"
pipx=$(command -v pipx) || { echo "install.sh needs pipx" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/home" "$work/tools"
ln -s "$pipx" "$work/tools/pipx"
export HOME=$work/home USE_EMOJI=0
unset PIPX_HOME PIPX_BIN_DIR PIPX_MAN_DIR
export PATH=$HOME/.local/bin:/usr/local/bin:/usr/bin:$work/tools
cd "$HOME" || exit 1

say "Install: clone the repository and install it with pipx"
run 'git clone -q --depth 1 https://github.com/luciusthorne/xray'
run "pipx install ${XRAY_TOUR_SOURCE:-./xray}"

say "Ready: xray is on your PATH"
run 'xray --version'
run 'xray --help | head -14'
