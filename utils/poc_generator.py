import subprocess
from PIL import Image, ImageDraw, ImageFont
import os


# ----------------------------
# Run command and capture output
# ----------------------------
def run_command_capture(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


# ----------------------------
# Convert text to image
# ----------------------------
def text_to_image(text, output_file):
    lines = text.split("\n")

    width = 1000
    line_height = 20
    height = line_height * (len(lines) + 5)

    image = Image.new("RGB", (width, height), "black")
    draw = ImageDraw.Draw(image)

    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", 14)
    except:
        font = ImageFont.load_default()

    y = 10
    for line in lines:
        draw.text((10, y), line, fill="white", font=font)
        y += line_height

    image.save(output_file)


# ----------------------------
# Nmap PoC
# ----------------------------
def generate_nmap_poc(target):
    os.makedirs("runs/poc", exist_ok=True)

    cmd = [
        "nmap",
        "--script", "vuln",
        target
    ]

    output = run_command_capture(cmd)

    output_file = f"runs/poc/nmap_{target}.png"
    text_to_image(output, output_file)

    return output_file


# ----------------------------
# SSL PoC
# ----------------------------
def generate_ssl_poc(target):
    os.makedirs("runs/poc", exist_ok=True)

    cmd = [
        "testssl.sh",
        "-B",
        target
    ]

    output = run_command_capture(cmd)

    output_file = f"runs/poc/ssl_{target}.png"
    text_to_image(output, output_file)

    return output_file