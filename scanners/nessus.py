import os
import time

import requests


class NessusScanner:
    def __init__(self, config):
        self.url = config["url"].rstrip("/")
        self.headers = {
            "X-ApiKeys": f'accessKey={config["access_key"]}; secretKey={config["secret_key"]}',
            "Content-Type": "application/json",
        }
        self.template_uuid = config["template_uuid"]

    def _request_json(self, method, path, **kwargs):
        response = requests.request(
            method,
            f"{self.url}{path}",
            headers=self.headers,
            timeout=60,
            **kwargs,
        )
        response.raise_for_status()
        return response.json()

    # ----------------------------
    # Create Scan
    # ----------------------------
    def create_scan(self, targets):
        payload = {
            "uuid": self.template_uuid,
            "settings": {
                "name": f"Vaptor Scan {int(time.time())}",
                "text_targets": ",".join(targets),
            },
        }

        res = self._request_json("POST", "/scans", json=payload)
        return res["scan"]["id"]

    # ----------------------------
    # Launch Scan
    # ----------------------------
    def launch_scan(self, scan_id):
        self._request_json("POST", f"/scans/{scan_id}/launch")

    # ----------------------------
    # Wait for Completion
    # ----------------------------
    def wait_for_scan(self, scan_id):
        while True:
            res = self._request_json("GET", f"/scans/{scan_id}")
            status = res["info"]["status"]

            print(f"[+] Nessus Status: {status}")

            if status == "completed":
                return

            if status in {"canceled", "stopped", "error"}:
                raise RuntimeError(f"Nessus scan ended with status: {status}")

            time.sleep(15)

    # ----------------------------
    # Export Results
    # ----------------------------
    def export_scan(self, scan_id):
        export = self._request_json("POST", f"/scans/{scan_id}/export", json={"format": "json"})
        file_id = export["file"]

        while True:
            status = self._request_json("GET", f"/scans/{scan_id}/export/{file_id}/status")

            if status["status"] == "ready":
                break

            time.sleep(5)

        download = requests.get(
            f"{self.url}/scans/{scan_id}/export/{file_id}/download",
            headers=self.headers,
            timeout=60,
        )
        download.raise_for_status()

        os.makedirs("runs", exist_ok=True)
        output_file = f"runs/nessus_{scan_id}.json"

        with open(output_file, "wb") as f:
            f.write(download.content)

        return output_file
