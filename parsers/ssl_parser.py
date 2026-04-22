import json

def parse_testssl(json_file, target, scan_id):
    findings = []

    with open(json_file, "r") as f:
        data = json.load(f)

    entries = data if isinstance(data, list) else data.get("results", data.get("entries", []))

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        severity = entry.get("severity", "").lower()
        finding = entry.get("finding", "").lower()
        issue = entry.get("id") or entry.get("finding") or "SSL Issue"

        # Filter only vulnerabilities
        if (
            severity in ["high", "medium"] or
            any(word in finding for word in ["weak", "deprecated", "insecure", "vulnerable"])
        ):
            findings.append({
                "target": target,
                "port": entry.get("port", ""),
                "service": "ssl",
                "tool": "testssl",
                "severity": severity,
                "issue": issue,
                "cve": [],
                "cvss_score": "",
                "description": entry.get("finding", ""),
                "recommendation": "Harden SSL/TLS configuration",
                "scan_id": scan_id
            })

    return findings
