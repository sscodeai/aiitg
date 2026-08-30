#!/usr/bin/env python3
"""Generate a terminal-style demo GIF for aiitg (AI Input Trust Gateway).

Renders the REAL CLI output (captured via subprocess) as an animated terminal
with a typing effect, then writes a looping GIF. Pure Pillow — no external
screencast tools needed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent  # repo root (scripts/..)
VENV_PY = REPO / ".venv" / "bin" / "python"
ENV = {"PYTHONPATH": str(REPO / "src")}

BG = (18, 24, 34)          # dark terminal background
FG = (200, 220, 240)       # default text
GREEN = (80, 250, 123)     # prompt / success
CYAN = (139, 233, 253)     # command names
YELLOW = (241, 250, 140)   # warnings
RED = (255, 121, 198)      # block / dangerous
GRAY = (120, 135, 150)     # muted

FONT_SIZE = 16
LINE_H = 24
PAD_X = 16
PAD_Y = 14

# find a monospace font
_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf",
]
FONT_PATH = next((p for p in _FONT_CANDIDATES if Path(p).exists()), None)


def load_font(size: int):
    if FONT_PATH:
        return ImageFont.truetype(FONT_PATH, size)
    return ImageFont.load_default()


def run_cli(args: list[str]) -> tuple[str, int]:
    r = subprocess.run(
        [str(VENV_PY), "-m", "aiitg.cli.main", *args],
        capture_output=True, text=True, env=ENV, cwd=str(REPO),
    )
    # strip runpy warnings (they pollute stdout)
    out = "\n".join(
        ln for ln in (r.stdout + r.stderr).splitlines()
        if "RuntimeWarning" not in ln and "runpy" not in ln and "may result" not in ln and "found in sys.modules" not in ln
    )
    return out.strip(), r.returncode


# --- scene definition: (title, command args, output coloring hints) ---
SCENES: list[dict] = [
    {
        "title": "1 · Scan a clean document",
        "args": ["scan", "/tmp/aitg-demo/proposal_clean.docx", "--format", "rich"],
        "ok_color": GREEN,
    },
    {
        "title": "2 · Scan a document with hidden zero-width instruction",
        "args": ["scan", "/tmp/aitg-demo/proposal_evil.docx", "--format", "rich"],
        "ok_color": RED,
    },
    {
        "title": "3 · Trust label: dangerous (hidden content detected)",
        "args": ["trust", "/tmp/aitg-demo/proposal_evil.docx", "--format", "rich"],
        "ok_color": RED,
    },
    {
        "title": "4 · Sanitize: strip hidden content → safe text",
        "args": ["sanitize", "/tmp/aitg-demo/proposal_evil.docx", "--mode", "redact"],
        "ok_color": GREEN,
    },
    {
        "title": "5 · Policy: block dangerous documents before they reach an LLM",
        "args": ["policy", "/tmp/aitg-demo/proposal_evil.docx", "--format", "rich"],
        "ok_color": RED,
    },
]


def colorize_line(line: str) -> list[tuple[str, tuple[int, int, int]]]:
    """Very light ANSI-ish coloring by content (best-effort, no ANSI codes)."""
    low = line.lower()
    if low.startswith("ai input trust gateway"):
        return [(line, CYAN)]
    if "no evidence" in low:
        return [(line, GREEN)]
    if "block" in low or "dangerous" in low or "high" in low:
        return [(line, RED)]
    if "caution" in low or "medium" in low or "finding" in low or "sanitized" in low:
        return [(line, YELLOW)]
    if "decision" in low or "policy" in low or "allow" in low or "quarantine" in low:
        return [(line, GREEN)]
    if "┃" in line or "┏" in line or "┗" in line or "┡" in line or "└" in line or "┌" in line or "┐" in line or "┘" in line:
        return [(line, GRAY)]
    if "│" in line:
        return [(line, FG)]
    return [(line, FG)]


def render_frame(
    lines: list[tuple[str, tuple[int, int, int]]],
    title: str,
    cmdline: str,
    visible: int,  # how many output lines are "typed" so far
) -> Image.Image:
    """Render one frame: title bar + prompt + typed output."""
    font = load_font(FONT_SIZE)
    bold_font = load_font(FONT_SIZE + 2)
    title_font = load_font(FONT_SIZE + 4)

    # estimate width from the longest line
    all_lines = [cmdline] + [l for l, _ in lines[:visible]]
    max_w = max(len(l) for l in all_lines + [title]) if all_lines else 40
    width = max(620, PAD_X * 2 + max_w * FONT_SIZE // 2 + 40)
    height = PAD_Y * 2 + 40 + LINE_H * (visible + 2) + 30

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)

    # title bar
    d.rectangle([0, 0, width, 34], fill=(30, 40, 55))
    d.text((PAD_X, 8), "aiitg — AI Input Trust Gateway demo", font=title_font, fill=CYAN)
    d.rectangle([0, 34, width, 36], fill=(50, 65, 85))

    # command line (prompt)
    y = PAD_Y + 44
    d.text((PAD_X, y), "$ ", font=bold_font, fill=GREEN)
    d.text((PAD_X + 22, y), f"aiitg {cmdline}", font=bold_font, fill=FG)

    # typed output lines
    y += LINE_H + 6
    for line, color in lines[:visible]:
        d.text((PAD_X, y), line, font=font, fill=color)
        y += LINE_H

    # scene label
    d.text((PAD_X, height - 24), title, font=font, fill=GRAY)

    return img


def build_gif(out_path: Path, fps: int = 12) -> None:
    frames: list[Image.Image] = []
    for scene in SCENES:
        out, code = run_cli(scene["args"])
        lines = []
        for raw in out.splitlines():
            lines.extend(colorize_line(raw))
        cmdline = " ".join(scene["args"])

        # typing animation: reveal lines progressively
        steps = max(1, len(lines))
        for i in range(1, steps + 1):
            frames.append(render_frame(lines, scene["title"], cmdline, i))
        # hold last frame a bit longer
        for _ in range(fps):
            frames.append(render_frame(lines, scene["title"], cmdline, len(lines)))

    # duration per frame (ms)
    durations = [1000 // fps] * len(frames)
    # hold the very last frame of the whole GIF longer
    durations[-fps:] = [300] * fps

    frames[0].save(
        out_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=False,
    )
    print(f"wrote {out_path} ({len(frames)} frames, {fps}fps)")


if __name__ == "__main__":
    out = REPO / "assets" / "aiitg-demo.gif"
    out.parent.mkdir(exist_ok=True)
    build_gif(out)
