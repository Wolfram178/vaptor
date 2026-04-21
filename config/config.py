import json
import os
from cryptography.fernet import Fernet

CONFIG_FILE = "config/nessus_config.json"
KEY_FILE = "config/key.key"


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

    with open(CONFIG_FILE, "r") as f:
        data = json.load(f)

    try:
        data["access_key"] = cipher.decrypt(data["access_key"].encode()).decode()
        data["secret_key"] = cipher.decrypt(data["secret_key"].encode()).decode()
    except Exception:
        print("[ERROR] Failed to decrypt Nessus keys")
        return None

    return data


# ----------------------------
# Save Config (Encrypt)
# ----------------------------
def save_config(config):
    cipher = get_cipher()

    encrypted_config = config.copy()

    encrypted_config["access_key"] = cipher.encrypt(config["access_key"].encode()).decode()
    encrypted_config["secret_key"] = cipher.encrypt(config["secret_key"].encode()).decode()

    os.makedirs("config", exist_ok=True)

    with open(CONFIG_FILE, "w") as f:
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

    config = {
        "url": url,
        "access_key": access_key,
        "secret_key": secret_key,
        "template_uuid": template_uuid
    }

    save_config(config)

    print("[✓] Config saved securely (encrypted)")

    return config