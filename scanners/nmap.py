import os
import platform
import subprocess

from utils.logger import log_status
from utils.terminal_capture import run_with_script


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

        alive = is_host_alive(target)
        cmd = [
            "nmap",
            "-p-",
            "--open",
            "-sV",
            "-sC",
            "-T4",
        ]

        if not alive:
            cmd.append("-Pn")

        cmd.extend(["-oX", output_file, target])

        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        terminal_output = os.path.splitext(output_file)[0] + ".txt"
        success = run_with_script(cmd, terminal_output)

        if not success:
            log_status(target, "nmap", "failed")
            return False

        log_status(target, "nmap", "completed")
        return True

    except Exception:
        log_status(target, "nmap", "failed")
        return False
