"""Render a `script` log into terminal frames for a GIF.

Usage: render_gif.py LOG TITLE COLS ROWS
Writes frames/ and frames.txt (an ffmpeg concat list) in the current directory.
Understands SGR colours, carriage returns and erase-line; other escapes are dropped.
Lines that start with "$ " are typed out character by character.
"""
import re
import shutil
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

LOG, TITLE, COLS, ROWS = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
SIZE, PAD = 15, 16
REG = ImageFont.truetype("/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf", SIZE)
BOLD = ImageFont.truetype("/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Bold.ttf", SIZE)
BG, FG, DIM = (13, 17, 23), (214, 222, 235), (120, 130, 145)
COLORS = {
    31: (255, 123, 114), 32: (126, 231, 135), 33: (227, 179, 65), 34: (121, 192, 255),
    35: (210, 168, 255), 36: (92, 207, 230), 37: FG,
}
CW = int(REG.getlength("M"))
LH = int(SIZE * 1.35)
W, H = COLS * CW + 2 * PAD, ROWS * LH + 2 * PAD + 28

raw = Path(LOG).read_bytes().decode("utf-8", "replace")
body = raw[raw.index("\n") + 1:]
body = body[: body.rfind("\nScript done")]

screen = [[]]
col = 0
style = {"bold": False, "dim": False, "color": None}


def put(ch):
    global col
    line = screen[-1]
    if col >= COLS:
        screen.append([])
        line, col = screen[-1], 0
    cell = (ch, dict(style))
    if col < len(line):
        line[col] = cell
    else:
        line.append(cell)
    col += 1


def sgr(codes):
    for code in (codes.split(";") if codes else ["0"]):
        code = int(code or 0)
        if code == 0:
            style.update(bold=False, dim=False, color=None)
        elif code == 1:
            style["bold"] = True
        elif code == 2:
            style["dim"] = True
        elif code in (22,):
            style.update(bold=False, dim=False)
        elif code == 39:
            style["color"] = None
        elif 30 <= code <= 37 or 90 <= code <= 97:
            style["color"] = COLORS.get(code if code < 90 else code - 60)


def draw():
    image = Image.new("RGB", (W, H), BG)
    pen = ImageDraw.Draw(image)
    for i, color in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        pen.ellipse((PAD + i * 20, 10, PAD + i * 20 + 12, 22), fill=color)
    pen.text((W // 2, 16), TITLE, fill=DIM, font=REG, anchor="mm")
    for row, line in enumerate(screen[-ROWS:]):
        y = PAD + 28 + row * LH
        for c, (ch, st) in enumerate(line):
            color = st["color"] or (DIM if st["dim"] else FG)
            pen.text((PAD + c * CW, y), ch, fill=color, font=BOLD if st["bold"] else REG)
    return image


TOKEN = re.compile(r"(\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\r)")
frames = [(draw(), 0.8)]
pending = 0
for line in body.split("\n"):
    plain = re.sub(TOKEN, "", line)
    typing = plain.startswith("$ ")
    if typing and pending is not None and len(frames) > 1:
        frames.append((draw(), 2.4))  # let the previous output be read
    for part in TOKEN.split(line):
        if not part:
            continue
        if part == "\r":
            col = 0
            continue
        match = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if match:
            sgr(match.group(1))
        elif part == "\x1b[K":
            del screen[-1][col:]
        elif part.startswith("\x1b"):
            continue
        else:
            for ch in part:
                if ch == "\t":
                    for _ in range(8 - col % 8):
                        put(" ")
                    continue
                put(ch)
                if typing and col > 2 and ch != " " and col % 2 == 0:
                    frames.append((draw(), 0.03))
    screen.append([])
    col = 0
    pause = 0
    if plain.startswith("== "):
        pause = 1.6
    elif typing:
        pause = 0.7
    pending += 1
    if pause or pending >= 4:
        frames.append((draw(), pause or 0.08))
        pending = 0
frames.append((draw(), 4.0))

shutil.rmtree("frames", ignore_errors=True)
Path("frames").mkdir()
listing = []
for number, (image, seconds) in enumerate(frames):
    name = f"frames/f{number:04d}.png"
    image.save(name)
    listing.append(f"file '{name}'\nduration {seconds:.2f}")
listing.append(listing[-1].split("\n")[0])
Path("frames.txt").write_text("\n".join(listing) + "\n")
print(len(frames), "frames,", round(sum(s for _, s in frames), 1), "seconds", W, "x", H)
