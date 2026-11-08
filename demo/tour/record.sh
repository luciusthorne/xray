#!/usr/bin/env bash
# Record the tour scripts and render docs/tour-*.gif.
# Needs util-linux script, uv, ffmpeg, pipx (install tour), a JetBrains Mono Nerd Font,
# and the commands the tours read (jq, curl, xdg-utils, ripgrep, gh, coreutils).
# Usage: record.sh [install|options|code ...]   (default: all three)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
docs=$here/../../docs
cols=100 rows=32
declare -A titles=(
  [install]="xray — install"
  [options]="xray — options"
  [code]="xray — reading a command's code"
)
for name in "${@:-install options code}"; do
  for tour in $name; do
    out=$(mktemp -d)
    (cd "$out"
      script -q --log-out out.log -c "stty cols $cols rows $rows; $here/$tour.sh" >/dev/null
      uv run --isolated --with pillow python "$here/render_gif.py" out.log "${titles[$tour]}" "$cols" "$rows"
      ffmpeg -loglevel error -y -f concat -safe 0 -i frames.txt \
        -vf "fps=12,split[a][b];[a]palettegen=max_colors=48[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
        "$docs/tour-$tour.gif")
    rm -rf "$out"
    echo "wrote docs/tour-$tour.gif"
  done
done
