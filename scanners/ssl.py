import subprocess
from utils.logger import log_status

def run_testssl(target, output_file):
    try:
        subprocess.run(
            ["testssl.sh", "--warning", "off", "--jsonfile", output_file, target],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def run_ssl_stage(target, open_ports):
    log_status(target, "ssl", "running")

    output_base = f"runs/testssl_{target}.json"

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