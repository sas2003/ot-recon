# core/scanner.py
from ot_recon.core.paths import DISCOVERY_XML, SCAN_XML, UDP_SCAN_XML
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


# TCP ports covering Siemens (S7), Rockwell (EtherNet/IP), B&R (PVI/ANSL/
# SafeDESIGNER/mapp), and generic OT/IT exposure. Keep in sync with
# data/ports.yaml.
OT_TCP_PORTS = (
    "21,22,80,81,102,161,443,502,2222,4840,5900,"
    "8084,11159,11160,11169,20000,44818,50000,51000"
)

# UDP-only OT traffic that a plain -sT scan will never see (EtherNet/IP
# implicit I/O, SNMP). UDP scans are slower and need raw-socket privileges,
# so they're opt-in via --udp rather than part of the default scan.
OT_UDP_PORTS = "161,2222"


def scan_live_hosts(hosts, verbose=False, udp=False, tcp_ports=None, udp_ports=None,
                     tcp_timing=None, udp_timing=None):
    if not hosts:
        print("[-] No active hosts found.")
        return

    tcp_ports = tcp_ports or OT_TCP_PORTS
    tcp_timing = tcp_timing or "T5"

    print(f"[+] Scanning {len(hosts)} hosts for OT ports...")

    cmd = [
        "nmap",
        "-n",
        f"-{tcp_timing}",
        "-p", tcp_ports,
        "-sT",
        "-oX", str(SCAN_XML),
    ] + hosts

    run_cmd(cmd, verbose)

    print("[+] Targeted TCP scan complete.")

    if udp:
        scan_udp_ports(hosts, verbose, udp_ports=udp_ports, udp_timing=udp_timing)


def scan_udp_ports(hosts, verbose=False, udp_ports=None, udp_timing=None):
    udp_ports = udp_ports or OT_UDP_PORTS
    udp_timing = udp_timing or "T4"

    print(f"[+] Scanning {len(hosts)} hosts for UDP OT ports (requires root)...")

    cmd = [
        "nmap",
        "-n",
        f"-{udp_timing}",
        "-sU",
        "-p", udp_ports,
        "-oX", str(UDP_SCAN_XML),
    ] + hosts

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("[-] UDP scan failed (likely needs sudo/root privileges). Skipping.")
        if verbose:
            print(result.stderr)
        return

    if verbose:
        print(result.stdout)

    print("[+] UDP scan complete.")