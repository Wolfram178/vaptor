import json
import os

from cryptography.fernet import Fernet

CONFIG_FILE = "config/nessus_config.json"
KEY_FILE = "config/key.key"
DEFAULT_REQUEST_TIMEOUT = 60
DEFAULT_SCAN_TIMEOUT = 7200
DEFAULT_EXPORT_TIMEOUT = 600


def apply_defaults(config):
    config.setdefault("request_timeout", DEFAULT_REQUEST_TIMEOUT)
    config.setdefault("scan_timeout", DEFAULT_SCAN_TIMEOUT)
    config.setdefault("export_timeout", DEFAULT_EXPORT_TIMEOUT)
    return config


# ----------------------------
# Key Management
# ----------------------------
def generate_key():
    key = Fernet.generate_key()
    os.makedirs("config", exist_ok=True)

    with open(KEY_FILE, "wb") as f:
        f.write(key)

    return key


def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()

    with open(KEY_FILE, "rb") as f:
        return f.read()


def get_cipher():
    key = load_key()
    return Fernet(key)


# ----------------------------
# Load Config (Decrypt)
# ----------------------------
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None

    cipher = get_cipher()

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    try:
        data["access_key"] = cipher.decrypt(data["access_key"].encode()).decode()
        data["secret_key"] = cipher.decrypt(data["secret_key"].encode()).decode()
    except Exception:
        print("[ERROR] Failed to decrypt Nessus keys")
        return None

    return apply_defaults(data)


# ----------------------------
# Save Config (Encrypt)
# ----------------------------
def save_config(config):
    cipher = get_cipher()

    encrypted_config = apply_defaults(config.copy())
    encrypted_config["access_key"] = cipher.encrypt(config["access_key"].encode()).decode()
    encrypted_config["secret_key"] = cipher.encrypt(config["secret_key"].encode()).decode()

    os.makedirs("config", exist_ok=True)

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(encrypted_config, f, indent=4)


# ----------------------------
# Setup Config (First Run)
# ----------------------------
def setup_config():
    print("\n[+] Nessus Configuration Setup")

    url = input("Nessus URL (e.g. https://localhost:8834): ").strip()
    access_key = input("Access Key: ").strip()
    secret_key = input("Secret Key: ").strip()
    template_uuid = input("Scan Template UUID: ").strip()
    request_timeout = input(f"Request Timeout in seconds [{DEFAULT_REQUEST_TIMEOUT}]: ").strip()
    scan_timeout = input(f"Scan Timeout in seconds [{DEFAULT_SCAN_TIMEOUT}]: ").strip()
    export_timeout = input(f"Export Timeout in seconds [{DEFAULT_EXPORT_TIMEOUT}]: ").strip()

    def parse_timeout(value, default):
        return int(value) if value else default

    config = {
        "url": url,
        "access_key": access_key,
        "secret_key": secret_key,
        "template_uuid": template_uuid,
        "request_timeout": parse_timeout(request_timeout, DEFAULT_REQUEST_TIMEOUT),
        "scan_timeout": parse_timeout(scan_timeout, DEFAULT_SCAN_TIMEOUT),
        "export_timeout": parse_timeout(export_timeout, DEFAULT_EXPORT_TIMEOUT),
    }

    save_config(config)

    print("[OK] Config saved securely (encrypted)")

    return config
