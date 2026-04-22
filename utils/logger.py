def log_status(*parts):
    if len(parts) == 1:
        print(f"[+] {parts[0]}")
    elif len(parts) == 3:
        target, stage, status = parts
        print(f"[+] {target} [{stage}] {status}")
    else:
        print("[+] " + " ".join(str(part) for part in parts))


def log_info(message):
    print(f"[INFO] {message}")


def log_warning(message):
    print(f"[WARN] {message}")


def log_error(message):
    print(f"[ERROR] {message}")
