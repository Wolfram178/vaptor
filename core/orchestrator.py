import os
from time import perf_counter

from core.normalizer import safe_filename
from core.smart_scan import decide_scans
from db.db_manager import get_targets, save_finding, update_state
from utils.colors import info, success, warning, severity_color


# ----------------------------
# CLI Output Helpers
# ----------------------------
def print_nmap_summary(findings):
    if not findings:
        print(info("[NMAP] No open ports found"))
        return

    preview = ", ".join(f"{f['port']}({f['service']})" for f in findings[:5])
    suffix = " ..." if len(findings) > 5 else ""
    print(success(f"[NMAP] Open ports: {preview}{suffix}"))


def print_ssl_findings(findings):
    if not findings:
        print(info("[SSL] No SSL vulnerabilities found"))
        return

    issues = []
    for finding in findings[:5]:
        severity = finding.get("severity", "")
        issue = finding.get("issue", "")
        issues.append(severity_color(f"{issue}", severity))

    suffix = " ..." if len(findings) > 5 else ""
    print(warning(f"[SSL] Findings: {', '.join(issues)}{suffix}"))


# ----------------------------
# Nessus Pipeline (ALL targets)
# ----------------------------
def run_nessus_pipeline_all(targets, scan_id, config):
    from parsers.nessus_parser import parse_nessus
    from scanners.nessus import NessusScanner

    print(info("[NESSUS] Running..."))

    target_rows = get_targets(scan_id)

    for target_id, _target in target_rows:
        update_state(target_id, "nessus", "running")

    try:
        scanner = NessusScanner(config)

        nessus_scan_id = scanner.create_scan(targets)
        scanner.launch_scan(nessus_scan_id)
        scanner.wait_for_scan(nessus_scan_id)

        output_file = scanner.export_scan(nessus_scan_id)
        findings = parse_nessus(output_file, scan_id)

        for finding in findings:
            save_finding(finding)

        for target_id, _target in target_rows:
            update_state(target_id, "nessus", "completed")

        print(success("[NESSUS] Completed"))
        return True
    except Exception as e:
        for target_id, _target in target_rows:
            update_state(target_id, "nessus", "failed")
        print(warning(f"[WARN] Nessus scan failed: {e}"))
        return False


# ----------------------------
# Nmap Stage
# ----------------------------
def run_nmap_stage(target_id, target, scan_id):
    from parsers.nmap_parser import parse_nmap
    from scanners.nmap import run_nmap

    output_file = f"runs/nmap_{safe_filename(target)}.xml"

    print(info(f"[NMAP] Running on {target}..."))

    success_flag = run_nmap(target, output_file)
    terminal_output = f"runs/nmap_{safe_filename(target)}.txt"

    if not success_flag:
        update_state(target_id, "nmap", "failed")
        return []

    update_state(target_id, "nmap", "completed")

    findings, open_ports = parse_nmap(output_file, target, scan_id)

    for finding in findings:
        save_finding(finding)

    print_nmap_summary(findings)

    if findings:
        try:
            from utils.poc_generator import generate_nmap_poc

            generate_nmap_poc(target, terminal_output)
        except Exception as e:
            print(warning(f"[WARN] Nmap PoC skipped: {e}"))

    return open_ports


# ----------------------------
# SSL Stage
# ----------------------------
def run_ssl_pipeline(target_id, target, scan_id, open_ports):
    from parsers.ssl_parser import parse_testssl
    from scanners.ssl import run_ssl_stage

    print(info(f"[SSL] Running on {target}..."))

    output_file = run_ssl_stage(target, open_ports)
    terminal_output = f"runs/testssl_{safe_filename(target)}.txt"

    if not output_file:
        update_state(target_id, "ssl", "failed")
        return

    update_state(target_id, "ssl", "completed")

    findings = parse_testssl(output_file, target, scan_id)

    for finding in findings:
        save_finding(finding)

    print_ssl_findings(findings)

    if findings:
        try:
            from utils.poc_generator import generate_ssl_poc

            generate_ssl_poc(target, terminal_output)
        except Exception as e:
            print(warning(f"[WARN] SSL PoC skipped: {e}"))


# ----------------------------
# Full Pipeline
# ----------------------------
def run_full_pipeline(target_id, target, scan_id):
    print(info(f"\n[TARGET] {target}"))

    os.makedirs("runs", exist_ok=True)
    target_started = perf_counter()

    open_ports = run_nmap_stage(target_id, target, scan_id)
    actions = decide_scans(open_ports)

    print(info(f"[SCAN] Decisions: {actions}"))

    run_ssl_pipeline(target_id, target, scan_id, open_ports)

    if actions.get("http"):
        print(info(f"[HTTP] Checks on {target}"))

    if actions.get("ftp"):
        print(info(f"[FTP] Checks on {target}"))

    if actions.get("ssh"):
        print(info(f"[SSH] Checks on {target}"))

    if actions.get("smb"):
        print(info(f"[SMB] Checks on {target}"))

    elapsed = perf_counter() - target_started
    return elapsed
