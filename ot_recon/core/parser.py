# ot_recon/core/parser.py

import xml.etree.ElementTree as ET
from ot_recon.core.paths import SCAN_XML


def parse_results():
    print("[+] Parsing scan results...")

    try:  
        tree = ET.parse(SCAN_XML)

    except FileNotFoundError:
        print("[-] Discovery results not found.")
        return []

    except ET.ParseError:
        print("[-] Discovery XML is invalid.")
        return []    
    root = tree.getroot()

    results = []

    for host in root.findall("host"):
        ip = host.find("address").get("addr")

        ports = []

        for p in host.findall(".//port"):

            state = p.find("state").get("state")

            # Extract service info from Nmap
            service = p.find("service")

            if service is not None:
                service_name = service.get("name", "unknown")
            else:
                service_name = "unknown"

            if state in ["open", "filtered"]:

                ports.append({
                    "port": int(p.get("portid")),
                    "state": state,
                    "service": service_name
                })

        results.append({
            "ip": ip,
            "ports": ports
        })

    return results