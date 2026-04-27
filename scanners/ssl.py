import os

from utils.logger import log_status
from core.normalizer import safe_filename
from utils.terminal_capture import run_with_script

def run_testssl(target, output_file):
    command = ["testssl.sh", "--warning", "off", "--jsonfile", output_file, target]
    terminal_output = os.path.splitext(output_file)[0] + ".txt"
    return run_with_script(command, terminal_output)


def run_ssl_stage(target, open_ports):
    log_status(target, "ssl", "running")

    os.makedirs("runs", exist_ok=True)
    output_base = f"runs/testssl_{safe_filename(target)}.json"

    # Step 1: Try direct
    if run_testssl(target, output_base):
        log_status(target, "ssl", "completed")
        return output_base

    # Step 2: Fallback ports
    for port in open_ports:
        if port in [443, 8443, 9443, 80]:
            target_with_port = f"{target}:{port}"
            if run_testssl(target_with_port, output_base):
                log_status(target, "ssl", "completed")
                return output_base

    log_status(target, "ssl", "failed")
    return None
