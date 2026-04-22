import json


def parse_nessus(json_file, scan_id):
    findings = []

    with open(json_file, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        vulnerabilities = data
    else:
        vulnerabilities = data.get("vulnerabilities", data.get("vulns", []))

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue

        plugin_name = vuln.get("plugin_name", "")
        severity = vuln.get("severity", "")
        cves = vuln.get("cve", [])

        hosts = vuln.get("hosts", vuln.get("host", []))
        if isinstance(hosts, str):
            hosts = [hosts]

        for host in hosts:
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
