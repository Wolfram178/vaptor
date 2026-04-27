#!/usr/bin/env python3

import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.metadata import PackageNotFoundError, version
from time import perf_counter

from config.config import load_config, setup_config
from correlator.engine import correlate_findings
from core.input_handler import load_targets
from core.orchestrator import run_full_pipeline, run_nessus_pipeline_all
from db.db_manager import add_target, complete_scan, create_scan, get_findings, init_db
from output.excel_writer import export_report
from output.json_writer import write_json
from utils.cli_formatter import format_cli_output


def get_tool_version():
    try:
        return version("vaptor")
    except PackageNotFoundError:
        return "0.1.1"


def rows_to_dicts(rows):
    columns = [
        "id",
        "target",
        "port",
        "service",
        "tool",
        "severity",
        "issue",
        "cve",
        "cvss_score",
        "description",
        "recommendation",
        "scan_id",
        "timestamp",
    ]
    return [dict(zip(columns, row)) for row in rows]


def _print_banner(tool_version, args):
    banner = [
        "========================================",
        "   VAPTOR - VAPT AUTOMATION TOOL",
        "========================================",
    ]

    print(format_cli_output("\n".join(banner), "info"))
    print(format_cli_output(f"Version: {tool_version}", "success"))
    print(format_cli_output(f"Input: {args.input}", "info"))
    print(format_cli_output(f"Excel: {args.output}", "info"))
    print(format_cli_output(f"JSON: {args.json}", "info"))
    print(format_cli_output(f"Resume: {args.resume}", "info"))
    print(format_cli_output(f"Mode: {args.mode}", "info"))
    print(format_cli_output(f"Threads: {args.threads}", "info"))


def main():
    tool_version = get_tool_version()
    parser = argparse.ArgumentParser(description=f"Vaptor - VAPT Automation Tool v{tool_version}")

    parser.add_argument("-i", "--input", required=True, help="Input file with targets")
    parser.add_argument("-o", "--output", default="report.xlsx", help="Excel output file")
    parser.add_argument("--json", default="report.json", help="JSON output file")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("--mode", choices=["raw", "normalized"], default="raw", help="Vulnerability processing mode")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel threads")
    parser.add_argument("--version", action="version", version=f"Vaptor {tool_version}")

    args = parser.parse_args()
    started_at = perf_counter()

    _print_banner(tool_version, args)

    init_db()

    config = load_config()
    if not config:
        config = setup_config()

    targets = load_targets(args.input)
    if not targets:
        print(format_cli_output("No valid targets found.", "error"))
        return

    print(format_cli_output(f"Loaded {len(targets)} target(s)", "success"))

    scan_id = create_scan()
    print(format_cli_output(f"Created Scan ID: {scan_id}", "success"))

    os.makedirs("runs", exist_ok=True)
    print(format_cli_output("Starting parallel scanning", "info"))

    def process_target(target):
        target_started = perf_counter()
        target_id = add_target(scan_id, target)
        elapsed_stage = run_full_pipeline(target_id, target, scan_id)
        elapsed = elapsed_stage if elapsed_stage is not None else perf_counter() - target_started
        print(format_cli_output(f"[OK] Target completed in {elapsed:.1f} sec: {target}", "success"))
        return target

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_target, target) for target in targets]

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(format_cli_output(str(e), "error"))

    run_nessus_pipeline_all(targets, scan_id, config)

    complete_scan(scan_id)
    total_elapsed = perf_counter() - started_at
    print(format_cli_output(f"Scan completed successfully in {total_elapsed:.1f} sec", "success"))

    print(format_cli_output("Generating reports", "info"))

    raw_findings = get_findings(scan_id)
    findings = rows_to_dicts(raw_findings)
    print(format_cli_output(f"Raw findings: {len(findings)}", "info"))

    print(format_cli_output("Correlating findings", "info"))
    correlated = correlate_findings(findings)
    print(format_cli_output(f"Correlated findings: {len(correlated)}", "info"))

    export_report(correlated, args.output)
    print(format_cli_output(f"Excel report generated: {args.output}", "success"))

    write_json(correlated, args.json)
    print(format_cli_output(f"JSON report generated: {args.json}", "success"))


if __name__ == "__main__":
    main()
