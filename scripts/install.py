#!/usr/bin/env python3

import shutil
import subprocess
import sys
from pathlib import Path


def run(cmd, cwd):
    print(f"[+] Running: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def main():
    repo_root = Path(__file__).resolve().parents[1]
    pipx = shutil.which("pipx")

    try:
        if pipx:
            run(["pipx", "install", "--force", "."], repo_root)
        else:
            run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], repo_root)
            run([sys.executable, "-m", "pip", "install", "--user", "."], repo_root)

        print("[OK] Vaptor is installed.")
        print("[OK] You can now run: vaptor -i <targets.txt>")

    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] Installation failed: {exc}")
        sys.exit(exc.returncode)


if __name__ == "__main__":
    main()
