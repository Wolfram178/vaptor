import os
import re
import shlex
import shutil
import subprocess


ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
SCRIPT_START_RE = re.compile(r"(?m)^Script started.*(?:\r?\n|$)")
SCRIPT_DONE_RE = re.compile(r"(?m)^Script done.*(?:\r?\n|$)")


def _command_to_string(command):
    if isinstance(command, str):
        return command

    return shlex.join(command)


def clean_terminal_output(text):
    if not text:
        return ""

    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = ANSI_ESCAPE_RE.sub("", cleaned)
    cleaned = SCRIPT_START_RE.sub("", cleaned)
    cleaned = SCRIPT_DONE_RE.sub("", cleaned)
    cleaned = "\n".join(line.rstrip() for line in cleaned.splitlines())
    cleaned = cleaned.strip()

    if cleaned:
        cleaned += "\n"

    return cleaned


def run_with_script(command, output_file):
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    script_cmd = shutil.which("script")
    command_str = _command_to_string(command)

    try:
        if script_cmd:
            result = subprocess.run(
                [script_cmd, "-q", "-c", command_str, output_file],
                check=False,
            )
            returncode = result.returncode
        else:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=isinstance(command, str),
            )
            with open(output_file, "w", encoding="utf-8", errors="ignore") as f:
                f.write(result.stdout or "")
            returncode = result.returncode

        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                cleaned = clean_terminal_output(f.read())
            with open(output_file, "w", encoding="utf-8", errors="ignore") as f:
                f.write(cleaned)

        return returncode == 0

    except Exception as e:
        with open(output_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write(clean_terminal_output(f"[ERROR] {e}\n"))
        return False
