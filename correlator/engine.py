from collections import defaultdict
from utils.vuln_categorizer import categorize_vulnerability


def correlate_findings(findings):
    correlated = {}

    for f in findings:
        target = f.get("target")
        issue = f.get("issue", "")
        desc = f.get("description", "")

        category = categorize_vulnerability(issue, desc)

        key = (target, category)

        if key not in correlated:
            correlated[key] = {
                "target": target,
                "category": category,
                "tools": set(),
                "issues": set(),
                "cve": set(),
                "severity": f.get("severity", ""),
                "description": set(),
                "recommendation": f.get("recommendation", "")
            }

        entry = correlated[key]

        # merge tools
        entry["tools"].add(f.get("tool", ""))

        # merge issue names
        entry["issues"].add(issue)

        # merge CVEs (handle string or list)
        cve = f.get("cve", "")
        if isinstance(cve, str):
            if cve:
                entry["cve"].update(cve.split(","))
        elif isinstance(cve, list):
            entry["cve"].update(cve)

        # merge descriptions
        entry["description"].add(desc)

    # convert sets → clean output
    results = []

    for entry in correlated.values():
        results.append({
            "target": entry["target"],
            "category": entry["category"],
            "tools": ", ".join(filter(None, entry["tools"])),
            "issue": " | ".join(filter(None, entry["issues"])),
            "cve": ", ".join(filter(None, entry["cve"])),
            "severity": entry["severity"],
            "description": " | ".join(filter(None, entry["description"])),
            "recommendation": entry["recommendation"]
        })

    return results