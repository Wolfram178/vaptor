import os
import time


def capture_text_window(text_file, output_path, title, accent_color):
    try:
        import tkinter as tk
        from tkinter import scrolledtext
    except Exception:
        return False

    try:
        from mss import mss
        from PIL import Image
    except Exception:
        return False

    if not os.path.exists(text_file):
        return False

    try:
        with open(text_file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read().strip()
    except Exception:
        return False

    try:
        root = tk.Tk()
        root.title(title)
        root.configure(bg="#0b0f14")
        root.geometry("1280x820+80+80")
        root.attributes("-topmost", True)

        header = tk.Frame(root, bg="#111827", height=44)
        header.pack(fill="x")

        title_label = tk.Label(
            header,
            text=title,
            bg="#111827",
            fg=accent_color,
            font=("Courier New", 13, "bold"),
            anchor="w",
            padx=16,
            pady=10,
        )
        title_label.pack(fill="x")

        body = tk.Frame(root, bg="#0b0f14")
        body.pack(fill="both", expand=True)

        terminal = scrolledtext.ScrolledText(
            body,
            bg="#050608",
            fg="#e5e7eb",
            insertbackground="#22c55e",
            font=("Courier New", 11),
            wrap="word",
            borderwidth=0,
            highlightthickness=0,
            padx=16,
            pady=16,
        )
        terminal.pack(fill="both", expand=True, padx=12, pady=12)
        terminal.insert("1.0", text if text.endswith("\n") else text + "\n")
        terminal.configure(state="disabled")

        root.update_idletasks()
        root.update()
        time.sleep(0.35)
        root.update_idletasks()

        x = root.winfo_rootx()
        y = root.winfo_rooty()
        width = root.winfo_width()
        height = root.winfo_height()

        with mss() as sct:
            shot = sct.grab({"left": x, "top": y, "width": width, "height": height})
            Image.frombytes("RGB", shot.size, shot.rgb).save(output_path)

        root.destroy()
        return True

    except Exception:
        try:
            root.destroy()
        except Exception:
            pass
        return False
