#!/usr/bin/env python3

import argparse
import os

from db.db_manager import (
    init_db,
    create_scan,
    add_target,
    complete_scan,
    get_findings
)

from core.orchestrator import (
    run_full_pipeline,  
    run_nessus_pipeline_all
)

from output.matrix_builder import build_matrix
from output.excel_writer import export_report
from output.json_writer import write_json

from correlator.engine import correlate_findings

from config.config import load_config, setup_config

from utils.colors import success, info

from concurrent.futures import ThreadPoolExecutor, as_completed

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
# Convert DB rows → dict
# ----------------------------
def rows_to_dicts(rows):
    columns = [
        "id","target","port","service","tool","severity","issue",
        "cve","cvss_score","description","recommendation","scan_id","timestamp"
    ]
    return [dict(zip(columns, row)) for row in rows]


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

    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of parallel threads"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Vaptor 0.1.0"
    )

    args = parser.parse_args()

    print(info("\n=== Vaptor ==="))
    print(f"[+] Input File: {args.input}")
    print(f"[+] Excel Output: {args.output}")
    print(f"[+] JSON Output: {args.json}")
    print(f"[+] Resume Mode: {args.resume}")
    print(f"[+] Mode: {args.mode}\n")
    print(f"[+] Threads: {args.threads}")

    # ----------------------------
    # Init DB
    # ----------------------------
    init_db()

    # ----------------------------
    # Load Config (Nessus)
    # ----------------------------
    config = load_config()
    if not config:
        config = setup_config()

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
    # Process Targets (Nmap + SSL)
    # ----------------------------
    print("\n[+] Starting Parallel Scanning...\n")

    def process_target(target):
        target_id = add_target(scan_id, target)
        run_full_pipeline(target_id, target, scan_id)
        return target


    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_target, target) for target in targets]

        for future in as_completed(futures):
            try:
                completed_target = future.result()
                print(f"[✓] Completed: {completed_target}")
            except Exception as e:
                print(f"[ERROR] {e}") 
   
    # ----------------------------
    # Run Nessus (ALL targets)
    # ----------------------------
    run_nessus_pipeline_all(targets, scan_id, config)

    # ----------------------------
    # Complete Scan
    # ----------------------------
    complete_scan(scan_id)

    print(success("\n[✓] Scan Completed Successfully"))

    # ----------------------------
    # Generate Reports
    # ----------------------------
    print("\n[+] Generating Reports...")

    raw_findings = get_findings(scan_id)
    findings = rows_to_dicts(raw_findings)

    print(f"[+] Total Raw Findings: {len(findings)}")

    # ----------------------------
    # Correlation
    # ----------------------------
    print("[+] Correlating Findings...")

    correlated = correlate_findings(findings)

    print(f"[+] Total Correlated Findings: {len(correlated)}")

    # ----------------------------
    # Matrix
    # ----------------------------
    matrix = build_matrix(correlated, mode=args.mode)
    export_report(matrix, correlated, args.output)

    print(f"[✓] Excel report generated: {args.output}")

    # ----------------------------
    # JSON Output
    # ----------------------------
    write_json(correlated, args.json)
    print(f"[✓] JSON report generated: {args.json}")


# ----------------------------
# Entry Point
# ----------------------------
if __name__ == "__main__":
    main()