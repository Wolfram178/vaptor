# output/matrix_builder.py

from collections import defaultdict


def build_matrix(findings, mode="raw"):
    matrix = defaultdict(set)

    for f in findings:
        target = f["target"]

        # If correlated data exists, prefer category
        if "category" in f:
            if mode == "normalized":
                vuln = f["category"]
            else:
                vuln = f["issue"].strip().lower()
        else:
            # fallback for raw findings (pre-correlation)
            if mode == "normalized":
                from utils.vuln_categorizer import categorize_vulnerability
                vuln = categorize_vulnerability(f["issue"], f["description"])
            else:
                vuln = f["issue"].strip().lower()

        matrix[vuln].add(target)

    return matrix