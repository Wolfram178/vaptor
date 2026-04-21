import json


def parse_nessus(json_file, scan_id):
    findings = []

    with open(json_file, "r") as f:
        data = json.load(f)

    for vuln in data.get("vulnerabilities", []):
        plugin_name = vuln.get("plugin_name", "")
        severity = vuln.get("severity", "")
        cves = vuln.get("cve", [])

        for host in vuln.get("hosts", []):
            findings.append({
                "target": host,
                "port": "",
                "service": "",
                "tool": "nessus",
                "severity": severity,
                "issue": plugin_name,
                "cve": cves,
                "cvss_score": "",
                "description": vuln.get("description", ""),
                "recommendation": vuln.get("solution", ""),
                "scan_id": scan_id
            })

    return findings