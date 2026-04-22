import os

from db.db_manager import get_targets, save_finding, update_state

from utils.colors import info, success, warning, severity_color

from core.normalizer import safe_filename
from core.smart_scan import decide_scans


# ----------------------------
# CLI Output Helpers
# ----------------------------
def print_nmap_summary(findings):
    if not findings:
        print("\n[+] No open ports found")
        return

    print(info("\n[+] Open Ports:"))

    for f in findings:
        print(severity_color(f" - {f['port']} ({f['service']})", "low"))


def print_ssl_findings(findings):
    if not findings:
        print("\n[+] No SSL vulnerabilities found")
        return

    print(warning("\n[!] SSL Vulnerabilities:"))

    for f in findings:
        severity = f.get("severity", "")
        issue = f.get("issue", "")
        print(severity_color(f" - {issue}", severity))


# ----------------------------
# Nessus Pipeline (ALL targets)
# ----------------------------
def run_nessus_pipeline_all(targets, scan_id, config):
    from parsers.nessus_parser import parse_nessus
    from scanners.nessus import NessusScanner

    print("\n[+] Starting Nessus Scan (All Targets)")

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

        for f in findings:
            save_finding(f)

        for target_id, _target in target_rows:
            update_state(target_id, "nessus", "completed")

        print(success("[OK] Nessus Scan Completed & Stored"))
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

    print(info(f"[+] Running Nmap on {target}..."))

    success_flag = run_nmap(target, output_file)

    if not success_flag:
        update_state(target_id, "nmap", "failed")
        return []

    update_state(target_id, "nmap", "completed")

    findings, open_ports = parse_nmap(output_file, target, scan_id)

    for f in findings:
        save_finding(f)

    print_nmap_summary(findings)

    # Lazy PoC
    if findings:
        try:
            from utils.poc_generator import generate_nmap_poc

            generate_nmap_poc(target)
        except Exception as e:
            print(warning(f"[WARN] Nmap PoC skipped: {e}"))

    return open_ports


# ----------------------------
# SSL Stage
# ----------------------------
def run_ssl_pipeline(target_id, target, scan_id, open_ports):
    from parsers.ssl_parser import parse_testssl
    from scanners.ssl import run_ssl_stage

    print(info(f"[+] Running SSL scan on {target}..."))

    output_file = run_ssl_stage(target, open_ports)

    if not output_file:
        update_state(target_id, "ssl", "failed")
        return

    update_state(target_id, "ssl", "completed")

    findings = parse_testssl(output_file, target, scan_id)

    for f in findings:
        save_finding(f)

    print_ssl_findings(findings)

    # Lazy PoC
    if findings:
        try:
            from utils.poc_generator import generate_ssl_poc

            generate_ssl_poc(target)
        except Exception as e:
            print(warning(f"[WARN] SSL PoC skipped: {e}"))


# ----------------------------
# Full Pipeline
# ----------------------------
def run_full_pipeline(target_id, target, scan_id):
    print(info(f"\n[+] Processing Target: {target}"))

    os.makedirs("runs", exist_ok=True)

    # Step 1: Nmap
    open_ports = run_nmap_stage(target_id, target, scan_id)

    # Step 2: Smart Scan Decision
    actions = decide_scans(open_ports)

    print(info(f"[+] Smart Scan Decisions for {target}: {actions}"))

    # Step 3: ALWAYS run SSL
    run_ssl_pipeline(target_id, target, scan_id, open_ports)

    # Step 4: Conditional Scans (future modules)
    if actions.get("http"):
        print(info(f"[+] Running HTTP checks on {target}"))

    if actions.get("ftp"):
        print(info(f"[+] Running FTP checks on {target}"))

    if actions.get("ssh"):
        print(info(f"[+] Running SSH checks on {target}"))

    if actions.get("smb"):
        print(info(f"[+] Running SMB checks on {target}"))
