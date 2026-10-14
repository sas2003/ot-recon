# ot_recon/core/parser.py

import xml.etree.ElementTree as ET
from ot_recon.core.paths import SCAN_XML, UDP_SCAN_XML


def _parse_nmap_xml(path, protocol="tcp"):
    """Parse a single nmap XML file into {ip: [port_dict, ...]}."""

    try:
        tree = ET.parse(path)
    except FileNotFoundError:
        return {}
    except ET.ParseError:
        print(f"[-] {path} is invalid XML, skipping.")
        return {}

    root = tree.getroot()
    by_host = {}

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

            # nmap reports "open|filtered" for UDP ports it can't be sure
            # about; treat that the same way as "filtered" so it still
            # surfaces to the operator instead of being silently dropped.
            if state in ["open", "filtered", "open|filtered"]:

                ports.append({
                    "port": int(p.get("portid")),
                    "state": "filtered" if state == "open|filtered" else state,
                    "service": service_name,
                    "transport": protocol
                })

        by_host[ip] = ports

    return by_host


def parse_results():
    print("[+] Parsing scan results...")

    tcp_hosts = _parse_nmap_xml(SCAN_XML, protocol="tcp")

    if not tcp_hosts:
        print("[-] TCP scan results not found or empty.")

    udp_hosts = _parse_nmap_xml(UDP_SCAN_XML, protocol="udp")

    if udp_hosts:
        print(f"[+] Merging UDP results for {len(udp_hosts)} host(s)")

    results = []

    for ip, ports in tcp_hosts.items():
        ports = list(ports) + udp_hosts.get(ip, [])

        results.append({
            "ip": ip,
            "ports": ports
        })

    return results