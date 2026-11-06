#!/usr/bin/env bash
# Record run.sh and render docs/xz-demo.gif. Needs util-linux script, uv, ffmpeg and a JetBrains Mono font.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(mktemp -d)
cd "$out"
XRAY_DEMO_WORK=/tmp/xz script -q --log-out out.log -c "stty cols 104 rows 36; $here/run.sh" >/dev/null
uv run --isolated --with pillow python "$here/render_gif.py"
ffmpeg -loglevel error -y -f concat -safe 0 -i frames.txt \
  -vf "fps=10,split[a][b];[a]palettegen=max_colors=32[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
  "$here/../../docs/xz-demo.gif"
echo "wrote docs/xz-demo.gif"
