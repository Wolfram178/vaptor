import os

from core.normalizer import safe_filename


# ----------------------------
# Nmap PoC Screenshot
# ----------------------------
def generate_nmap_poc(target):
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("[WARN] Pillow not installed, skipping Nmap PoC")
        return

    try:
        os.makedirs("runs/poc", exist_ok=True)

        output_path = f"runs/poc/nmap_{safe_filename(target)}.png"

        img = Image.new("RGB", (1000, 400), color=(0, 0, 0))
        draw = ImageDraw.Draw(img)

        text = f"Nmap PoC for {target}"

        draw.text((20, 20), text, fill=(0, 255, 0))

        img.save(output_path)

        print(f"[+] Nmap PoC saved: {output_path}")

    except Exception as e:
        print(f"[ERROR] Failed to generate Nmap PoC: {e}")


# ----------------------------
# SSL PoC Screenshot
# ----------------------------
def generate_ssl_poc(target):
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("[WARN] Pillow not installed, skipping SSL PoC")
        return

    try:
        os.makedirs("runs/poc", exist_ok=True)

        output_path = f"runs/poc/ssl_{safe_filename(target)}.png"

        img = Image.new("RGB", (1000, 400), color=(0, 0, 0))
        draw = ImageDraw.Draw(img)

        text = f"SSL PoC for {target}"

        draw.text((20, 20), text, fill=(255, 0, 0))

        img.save(output_path)

        print(f"[+] SSL PoC saved: {output_path}")

    except Exception as e:
        print(f"[ERROR] Failed to generate SSL PoC: {e}")
