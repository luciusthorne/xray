"""Render a `script` log (SGR colours and newlines only) into terminal frames for a GIF."""
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

COLS, ROWS, SIZE, PAD = 104, 34, 15, 16
REG = ImageFont.truetype("/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf", SIZE)
BOLD = ImageFont.truetype("/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Bold.ttf", SIZE)
BG, FG, DIM, CYAN = (13, 17, 23), (214, 222, 235), (120, 130, 145), (92, 207, 230)
CW = int(REG.getlength("M"))
LH = int(SIZE * 1.35)
W, H = COLS * CW + 2 * PAD, ROWS * LH + 2 * PAD + 28

raw = Path("out.log").read_bytes().decode("utf-8", "replace")
body = raw[raw.index("\n") + 1:]
body = body[: body.rfind("\nScript done")]

screen = [[]]
style = {"bold": False, "dim": False, "color": None}


def put(ch):
    if len(screen[-1]) >= COLS:
        screen.append([])
    screen[-1].append((ch, dict(style)))


def sgr(codes):
    for code in (codes.split(";") if codes else ["0"]):
        code = int(code or 0)
        if code == 0:
            style.update(bold=False, dim=False, color=None)
        elif code == 1:
            style["bold"] = True
        elif code == 2:
            style["dim"] = True
        elif code == 36:
            style["color"] = CYAN


def draw():
    image = Image.new("RGB", (W, H), BG)
    pen = ImageDraw.Draw(image)
    for i, color in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        pen.ellipse((PAD + i * 20, 10, PAD + i * 20 + 12, 22), fill=color)
    pen.text((W // 2, 16), "xray — catching an xz-style backdoor", fill=DIM, font=REG, anchor="mm")
    for row, line in enumerate(screen[-ROWS:]):
        y = PAD + 28 + row * LH
        for col, (ch, st) in enumerate(line):
            color = st["color"] or (DIM if st["dim"] else FG)
            pen.text((PAD + col * CW, y), ch, fill=color, font=BOLD if st["bold"] else REG)
    return image


frames = []  # (image, seconds)
frames.append((draw(), 0.8))
pending = 0
for line in body.split("\n"):
    for part in re.split(r"(\x1b\[[0-9;]*m)", line.replace("\r", "")):
        match = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if match:
            sgr(match.group(1))
        else:
            for ch in part:
                put(ch)
    screen.append([])
    plain = re.sub(r"\x1b\[[0-9;]*m", "", line)
    pause = 0
    if plain.startswith("== "):
        pause = 2.0
    elif plain.startswith("$ "):
        pause = 0.8
    elif re.search(r"BREACH|Capabilities gained|marker file|payload was stopped|OK: \d+ entries|^\s+\+ ", plain):
        pause = 1.6
    pending += 1
    if pause or pending >= 3:
        frames.append((draw(), pause or 0.1))
        pending = 0
frames.append((draw(), 6.0))

import shutil

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
