import json
import os

CONFIG_FILE = "config/nessus_config.json"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None

    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def save_config(config):
    os.makedirs("config", exist_ok=True)

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


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
    return config