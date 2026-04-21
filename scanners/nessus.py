import requests
import time


class NessusScanner:
    def __init__(self, config):
        self.url = config["url"]
        self.headers = {
            "X-ApiKeys": f'accessKey={config["access_key"]}; secretKey={config["secret_key"]}',
            "Content-Type": "application/json"
        }
        self.template_uuid = config["template_uuid"]

    # ----------------------------
    # Create Scan
    # ----------------------------
    def create_scan(self, targets):
        payload = {
            "uuid": self.template_uuid,
            "settings": {
                "name": f"Vaptor Scan {int(time.time())}",
                "text_targets": ",".join(targets)
            }
        }

        res = requests.post(
            f"{self.url}/scans",
            headers=self.headers,
            json=payload
        ).json()

        return res["scan"]["id"]

    # ----------------------------
    # Launch Scan
    # ----------------------------
    def launch_scan(self, scan_id):
        requests.post(
            f"{self.url}/scans/{scan_id}/launch",
            headers=self.headers
        )

    # ----------------------------
    # Wait for Completion
    # ----------------------------
    def wait_for_scan(self, scan_id):
        while True:
            res = requests.get(
                f"{self.url}/scans/{scan_id}",
                headers=self.headers
            ).json()

            status = res["info"]["status"]

            print(f"[+] Nessus Status: {status}")

            if status == "completed":
                break

            time.sleep(15)

    # ----------------------------
    # Export Results
    # ----------------------------
    def export_scan(self, scan_id):
        export = requests.post(
            f"{self.url}/scans/{scan_id}/export",
            headers=self.headers,
            json={"format": "json"}
        ).json()

        file_id = export["file"]

        while True:
            status = requests.get(
                f"{self.url}/scans/{scan_id}/export/{file_id}/status",
                headers=self.headers
            ).json()

            if status["status"] == "ready":
                break

            time.sleep(5)

        download = requests.get(
            f"{self.url}/scans/{scan_id}/export/{file_id}/download",
            headers=self.headers
        )

        output_file = f"runs/nessus_{scan_id}.json"

        with open(output_file, "wb") as f:
            f.write(download.content)

        return output_file