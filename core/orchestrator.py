import os

from scanners.nmap import run_nmap
from scanners.ssl import run_ssl_stage

from parsers.nmap_parser import parse_nmap
from parsers.ssl_parser import parse_testssl

from db.db_manager import update_state, save_finding

from utils.poc_generator import generate_nmap_poc, generate_ssl_poc

from scanners.nessus import NessusScanner
from parsers.nessus_parser import parse_nessus
from db.db_manager import save_finding

from utils.colors import success, info, warning, error, severity_color

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

        colored_issue = severity_color(f" - {issue}", severity)

        print(colored_issue)

def run_nessus_pipeline_all(targets, scan_id, config):
    print("\n[+] Starting Nessus Scan (All Targets)")

    scanner = NessusScanner(config)

    nessus_scan_id = scanner.create_scan(targets)

    scanner.launch_scan(nessus_scan_id)
    scanner.wait_for_scan(nessus_scan_id)

    output_file = scanner.export_scan(nessus_scan_id)

    findings = parse_nessus(output_file, scan_id)

    for f in findings:
        save_finding(f)

    print("[✓] Nessus Scan Completed & Stored")

# ----------------------------
# Nmap Stage
# ----------------------------
def run_nmap_stage(target_id, target, scan_id):
    output_file = f"runs/nmap_{target}.xml"

    success = run_nmap(target, output_file)

    if not success:
        update_state(target_id, "nmap", "failed")
        return []

    update_state(target_id, "nmap", "completed")

    findings, open_ports = parse_nmap(output_file, target, scan_id)

    # Save findings to DB
    for f in findings:
        save_finding(f)

    # CLI Output
    print_nmap_summary(findings)

    # Generate PoC only if useful findings exist
    if findings:
        generate_nmap_poc(target)

    return open_ports


# ----------------------------
# SSL Stage
# ----------------------------
def run_ssl_pipeline(target_id, target, scan_id, open_ports):
    output_file = run_ssl_stage(target, open_ports)

    if not output_file:
        update_state(target_id, "ssl", "failed")
        return

    update_state(target_id, "ssl", "completed")

    findings = parse_testssl(output_file, target, scan_id)

    # Save findings to DB
    for f in findings:
        save_finding(f)

    # CLI Output FIRST
    print_ssl_findings(findings)

    # Generate PoC only if vulnerabilities exist
    if findings:
        generate_ssl_poc(target)


# ----------------------------
# Full Pipeline
# ----------------------------
def run_full_pipeline(target_id, target, scan_id):
    print(f"\n[+] Processing Target: {target}")

    # Ensure runs directory exists
    os.makedirs("runs", exist_ok=True)

    # Step 1: Nmap
    open_ports = run_nmap_stage(target_id, target, scan_id)

    # Step 2: Smart Scan Decision
    actions = decide_scans(open_ports)

    print(info(f"[+] Smart Scan Decisions for {target}: {actions}"))

    # ALWAYS run SSL
    run_ssl_pipeline(target_id, target, scan_id, open_ports)

    # Conditional Scans
    if actions["http"]:
        print(info(f"[+] Running HTTP checks on {target}"))

    if actions["ftp"]:
        print(info(f"[+] Running FTP checks on {target}"))

    if actions["ssh"]:
        print(info(f"[+] Running SSH checks on {target}"))

    if actions["smb"]:
        print(info(f"[+] Running SMB checks on {target}"))