# core/scanner.py

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
        "-oX", "output/discovery.xml",
        target
    ]

    run_cmd(cmd, verbose)
    print("[+] Discovery complete.")

    return parse_discovery()


def parse_discovery():
    hosts = []

    tree = ET.parse("output/discovery.xml")
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
        "-T4",
        "-p", "21,22,80,102,502,4840,5900,44818,20000",
        "-sT",
        "-oX", "output/scan.xml",
    ] + hosts

    run_cmd(cmd, verbose)

    print("[+] Targeted scan complete.")