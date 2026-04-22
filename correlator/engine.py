from utils.vuln_categorizer import categorize_vulnerability


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "": -1,
}


def _severity_value(value):
    normalized = str(value).lower()
    if normalized.isdigit():
        return int(normalized)
    return SEVERITY_RANK.get(normalized, -1)


def correlate_findings(findings):
    correlated = {}

    for f in findings:
        target = f.get("target") or ""
        issue = f.get("issue") or ""
        desc = f.get("description") or ""

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
                entry["cve"].update(item.strip() for item in cve.split(",") if item.strip())
        elif isinstance(cve, list):
            entry["cve"].update(item.strip() for item in cve if item)

        # merge descriptions
        entry["description"].add(desc)
        if _severity_value(f.get("severity", "")) > _severity_value(entry["severity"]):
            entry["severity"] = f.get("severity", "")

    # convert sets to clean output
    results = []

    for key in sorted(correlated.keys(), key=lambda item: (item[0], item[1])):
        entry = correlated[key]
        results.append({
            "target": entry["target"],
            "category": entry["category"],
            "tools": ", ".join(sorted(filter(None, entry["tools"]))),
            "issue": " | ".join(sorted(filter(None, entry["issues"]))),
            "cve": ", ".join(sorted(filter(None, entry["cve"]))),
            "severity": entry["severity"],
            "description": " | ".join(sorted(filter(None, entry["description"]))),
            "recommendation": entry["recommendation"]
        })

    return results
