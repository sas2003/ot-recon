# core/scanner.py
from ot_recon.core.paths import DISCOVERY_XML, SCAN_XML
import subprocess
import xml.etree.ElementTree as ET


def run_cmd(cmd, verbose=False):
    if verbose:
        subprocess.run(cmd)
    else:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def discover_hosts(target, verbose=False):
    print(f"[+] Discovering live hosts in {target}...")

    cmd = [
        "nmap",
        "-sn",
        "-oX", str(DISCOVERY_XML),
        target
    ]

    run_cmd(cmd, verbose)
    print("[+] Discovery complete.")

    return parse_discovery()


def parse_discovery():
    hosts = []

    try:  
        tree = ET.parse(DISCOVERY_XML)

    except FileNotFoundError:
        print("[-] Discovery results not found.")
        return []

    except ET.ParseError:
        print("[-] Discovery XML is invalid.")
        return []

    root = tree.getroot()

    for host in root.findall("host"):
        status = host.find("status").get("state")

        if status == "up":
            ip = host.find("address").get("addr")
            hosts.append(ip)

    print(f"[+] Found {len(hosts)} active hosts")
    return hosts


def scan_live_hosts(hosts, verbose=False):
    if not hosts:
        print("[-] No active hosts found.")
        return

    print(f"[+] Scanning {len(hosts)} hosts for OT ports...")

    cmd = [
        "nmap",
        "-n",
        "-T5",
        "-p", "21,22,80,102,502,4840,5900,44818,20000",
        "-sT",
        "-oX", str(SCAN_XML),
    ] + hosts

    run_cmd(cmd, verbose)

    print("[+] Targeted scan complete.")