#!/usr/bin/env python3

import argparse
import os

from db.db_manager import (init_db, create_scan, add_target, complete_scan)

from core.orchestrator import run_full_pipeline

from db.db_manager import get_findings
from output.matrix_builder import build_matrix
from output.excel_writer import export_matrix

# ----------------------------
# Load Targets from File
# ----------------------------
def load_targets(file_path):
    if not os.path.exists(file_path):
        print(f"[ERROR] Input file not found: {file_path}")
        exit(1)

    with open(file_path, "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    return targets


# ----------------------------
# Main Function
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Vaptor - VAPT Automation Tool")

    parser.add_argument("-i", "--input", required=True, help="Input file with targets")
    parser.add_argument("-o", "--output", default="report.xlsx", help="Excel output file")
    parser.add_argument("--json", default="report.json", help="JSON output file")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("--mode", choices=["raw", "normalized"], default="raw", help="Vulnerability processing mode")

    args = parser.parse_args()

    print("\n=== Vaptor ===")
    print(f"[+] Input File: {args.input}")
    print(f"[+] Excel Output: {args.output}")
    print(f"[+] JSON Output: {args.json}")
    print(f"[+] Resume Mode: {args.resume}\n")
    print(f"[+] Mode: {args.mode}")

    # ----------------------------
    # Init DB
    # ----------------------------
    init_db()

    # ----------------------------
    # Create Scan
    # ----------------------------
    scan_id = create_scan()
    print(f"[+] Created Scan ID: {scan_id}")

    # ----------------------------
    # Load Targets
    # ----------------------------
    targets = load_targets(args.input)

    if not targets:
        print("[ERROR] No valid targets found.")
        return

    print(f"[+] Loaded {len(targets)} target(s)\n")

    # ----------------------------
    # Ensure runs directory exists
    # ----------------------------
    os.makedirs("runs", exist_ok=True)

    # ----------------------------
    # Process Targets (FINAL FLOW)
    # ----------------------------
    for target in targets:
        target_id = add_target(scan_id, target)
        run_full_pipeline(target_id, target, scan_id)

    # ----------------------------
    # Complete Scan
    # ----------------------------
    complete_scan(scan_id)

    print("\n[✓] Scan Completed Successfully")

    # ----------------------------
    # Generate Excel Matrix
    # ----------------------------
    print("\n[+] Generating Vulnerability Matrix...")

    findings = get_findings(scan_id)

    columns = [
        "id","target","port","service","tool","severity","issue",
        "cve","cvss_score","description","recommendation","scan_id","timestamp"
    ]

    findings_dicts = [dict(zip(columns, row)) for row in findings]

    matrix = build_matrix(findings_dicts, mode=args.mode)

    export_matrix(matrix, args.output)

    print(f"[✓] Excel report generated: {args.output}")

# ----------------------------
# Entry Point
# ----------------------------
if __name__ == "__main__":
    main()