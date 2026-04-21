import xml.etree.ElementTree as ET

def parse_nmap(xml_file, target, scan_id):
    findings = []
    open_ports = []

    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state").get("state")

            if state == "open":
                port_id = port.get("portid")
                service = port.find("service").get("name")

                open_ports.append(int(port_id))

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