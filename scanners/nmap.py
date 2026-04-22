import os
import platform
import subprocess

from utils.logger import log_status


def is_host_alive(target):
    """Best-effort reachability check before a full Nmap run."""
    try:
        if platform.system().lower().startswith("win"):
            cmd = ["ping", "-n", "1", "-w", "1000", target]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", target]

        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        # If reachability probing fails, fall back to -Pn so Nmap still runs.
        return False

def run_nmap(target, output_file):
    try:
        log_status(target, "nmap", "running")

        # Check if host is alive
        alive = is_host_alive(target)

        if alive:
            cmd = [
                "nmap",
                "-p-",
                "--open",
                "-sV",
                "-sC",
                "-T4",
                "-oX",
                output_file,
                target
            ]
        else:
            cmd = [
                "nmap",
                "-Pn",
                "-p-",
                "--open",
                "-sV",
                "-sC",
                "-T4",
                "-oX",
                output_file,
                target
            ]

        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        subprocess.run(cmd, check=True)

        log_status(target, "nmap", "completed")
        return True

    except subprocess.CalledProcessError:
        log_status(target, "nmap", "failed")
        return False
