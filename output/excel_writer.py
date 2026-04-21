# output/excel_writer.py

import pandas as pd


# ----------------------------
# Matrix Sheet
# ----------------------------
def build_matrix_df(matrix):
    rows = []

    for vuln, targets in matrix.items():
        rows.append({
            "vulnerability": vuln,
            "targets": ", ".join(sorted(targets)),
            "count": len(targets)
        })

    df = pd.DataFrame(rows)

    if not df.empty:
        df = df.sort_values(by="count", ascending=False)

    return df


# ----------------------------
# Detailed Findings Sheet
# ----------------------------
def build_findings_df(findings):
    rows = []

    for f in findings:
        rows.append({
            "Target": f.get("target"),
            "Category": f.get("category"),
            "Severity": f.get("severity"),
            "Tools": f.get("tools"),
            "Issue": f.get("issue"),
            "CVE": f.get("cve"),
            "Description": f.get("description"),
            "Recommendation": f.get("recommendation"),
        })

    df = pd.DataFrame(rows)

    return df


# ----------------------------
# Export Excel (Multi-Sheet)
# ----------------------------
def export_report(matrix, findings, output_file):
    matrix_df = build_matrix_df(matrix)
    findings_df = build_findings_df(findings)

    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        matrix_df.to_excel(writer, sheet_name="Vulnerability Matrix", index=False)
        findings_df.to_excel(writer, sheet_name="Detailed Findings", index=False)