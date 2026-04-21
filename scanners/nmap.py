import subprocess
from utils.logger import log_status

def run_nmap(target, output_file):
    import subprocess
    from utils.logger import log_status

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

        subprocess.run(cmd, check=True)

        log_status(target, "nmap", "completed")
        return True

    except subprocess.CalledProcessError:
        log_status(target, "nmap", "failed")
        return False