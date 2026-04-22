import xml.etree.ElementTree as ET

def parse_nmap(xml_file, target, scan_id):
    findings = []
    open_ports = []

    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state_node = port.find("state")
            state = state_node.get("state") if state_node is not None else ""

            if state == "open":
                port_id = port.get("portid")
                service_node = port.find("service")
                service = service_node.get("name") if service_node is not None else "unknown"

                try:
                    open_ports.append(int(port_id))
                except (TypeError, ValueError):
                    continue

                findings.append({
                    "target": target,
                    "port": port_id,
                    "service": service,
                    "tool": "nmap",
                    "severity": "info",
                    "issue": f"Port {port_id} open ({service})",
                    "cve": [],
                    "cvss_score": "",
                    "description": f"Service {service} detected on port {port_id}",
                    "recommendation": "Verify if this port should be exposed",
                    "scan_id": scan_id
                })

    return findings, open_ports
