import os
import textwrap

from core.normalizer import safe_filename
from utils.screen_capture import capture_text_window


def _read_terminal_log(text_file):
    with open(text_file, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().strip()


def _wrap_terminal_text(text, width=110, max_lines=120):
    wrapped_lines = []

    for line in text.splitlines():
        if not line.strip():
            wrapped_lines.append("")
            continue

        wrapped_lines.extend(textwrap.wrap(line, width=width) or [""])

        if len(wrapped_lines) >= max_lines:
            wrapped_lines = wrapped_lines[:max_lines]
            wrapped_lines.append("... truncated ...")
            break

    return wrapped_lines or [""]


def _render_terminal_poc(text_file, output_path, title, accent_color):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("[WARN] Pillow not installed, skipping PoC generation")
        return

    try:
        if not os.path.exists(text_file):
            print(f"[WARN] Terminal log not found, skipping PoC: {text_file}")
            return

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        raw_text = _read_terminal_log(text_file)
        display_lines = [title, ""] + _wrap_terminal_text(raw_text)

        font = ImageFont.load_default()
        line_height = 14
        padding = 20
        width = 1200
        height = max(400, padding * 2 + line_height * len(display_lines) + 20)

        img = Image.new("RGB", (width, height), color=(10, 10, 10))
        draw = ImageDraw.Draw(img)

        y = padding
        draw.text((padding, y), title, fill=accent_color, font=font)
        y += line_height * 2

        for line in display_lines[2:]:
            draw.text((padding, y), line, fill=(235, 235, 235), font=font)
            y += line_height
            if y > height - padding:
                break

        img.save(output_path)
        print(f"[+] PoC saved: {output_path}")

    except Exception as e:
        print(f"[ERROR] Failed to generate PoC: {e}")


# ----------------------------
# Nmap PoC Screenshot
# ----------------------------
def generate_nmap_poc(target, text_file):
    output_path = f"runs/poc/nmap_{safe_filename(target)}.png"
    title = f"Nmap PoC for {target}"

    if capture_text_window(text_file, output_path, title, "#22c55e"):
        print(f"[+] PoC saved: {output_path}")
        return

    _render_terminal_poc(text_file, output_path, title, (0, 255, 0))


# ----------------------------
# SSL PoC Screenshot
# ----------------------------
def generate_ssl_poc(target, text_file):
    output_path = f"runs/poc/ssl_{safe_filename(target)}.png"
    title = f"SSL PoC for {target}"

    if capture_text_window(text_file, output_path, title, "#f87171"):
        print(f"[+] PoC saved: {output_path}")
        return

    _render_terminal_poc(text_file, output_path, title, (255, 80, 80))
