# core/parser.py

import xml.etree.ElementTree as ET


def parse_results():
    print("[+] Parsing scan results...")

    tree = ET.parse("output/scan.xml")
    root = tree.getroot()

    results = []

    for host in root.findall("host"):
        ip = host.find("address").get("addr")

        ports = []
        for p in host.findall(".//port"):
            state = p.find("state").get("state")

            if state in ["open", "filtered"]:
                ports.append({
                    "port": int(p.get("portid")),
                    "state": state
                })

        if ports:
            results.append({
                "ip": ip,
                "ports": ports
            })

    return results