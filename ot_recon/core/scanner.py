# core/scanner.py
from ot_recon.core.paths import DISCOVERY_XML, SCAN_XML, UDP_SCAN_XML
from ot_recon.core.netutils import get_local_ips
from ot_recon.core import runner
import ipaddress
import subprocess
import xml.etree.ElementTree as ET


def run_cmd(cmd, verbose=False, purpose=""):
    if verbose:
        runner.run(cmd, purpose=purpose)
    else:
        runner.run(cmd, purpose=purpose, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def get_nmap_version():
    """e.g. '7.94SVN', recorded in the report so findings can be tied to
    the exact scanner build. None if nmap can't be queried."""
    try:
        result = runner.run(["nmap", "--version"], purpose="version",
                            capture_output=True, text=True, timeout=10)
    except Exception:
        return None
    for line in (result.stdout or "").splitlines():
        if line.lower().startswith("nmap version"):
            return line.split("version", 1)[1].split("(")[0].strip()
    return None


def clear_artifacts():
    """Delete the previous run's nmap XML output before a new scan.

    The parser reads these files from disk, so without this a run that
    discovers nothing (or skips the UDP pass) would silently pick up the
    PREVIOUS run's hosts/ports - and the fingerprinter would then actively
    probe addresses that were never part of this scan."""

    for path in (DISCOVERY_XML, SCAN_XML, UDP_SCAN_XML):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def build_discovery_cmd(target, exclude=(), pacing=None):
    """The exact nmap command for the ping sweep. Shared by discover_hosts
    and --dry-run so the plan shown can never drift from what really runs."""

    cmd = ["nmap", "-sn"] + list(pacing or []) + ["-oX", str(DISCOVERY_XML)]

    if exclude:
        cmd += ["--exclude", ",".join(exclude)]

    cmd.append(target)
    return cmd


def _in_any_network(ip, networks):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks)


def discover_hosts(target, verbose=False, exclude_self=True, pacing=None, exclude=None):
    """Ping-sweep `target`. Never includes the do-not-scan list (`exclude`:
    IPs/CIDRs) or, when exclude_self, this machine's own addresses."""

    print(f"[+] Discovering live hosts in {target}...")

    local_ips = set()
    if exclude_self:
        local_ips = get_local_ips()
        if local_ips and verbose:
            print(f"[+] Excluding this machine's own address(es) from the scan: {', '.join(sorted(local_ips))}")

    user_excludes = [str(e).strip() for e in (exclude or []) if str(e).strip()]
    if user_excludes and verbose:
        print(f"[+] Do-not-scan list: {', '.join(user_excludes)}")

    # nmap's own --exclude keeps these addresses out of the ping sweep
    # entirely (nothing is ever sent to them), rather than scanning them
    # and filtering the result afterward.
    all_excludes = sorted(local_ips) + user_excludes

    cmd = build_discovery_cmd(target, all_excludes, pacing)
    run_cmd(cmd, verbose, purpose="discovery")
    print("[+] Discovery complete.")

    hosts = parse_discovery()

    # Safety net: if --exclude somehow didn't catch an address (e.g. one
    # nmap resolved differently than we detected it), filter it out here
    # too rather than carrying it into the scan.
    if all_excludes:
        networks = []
        for item in all_excludes:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass

        before = len(hosts)
        hosts = [h for h in hosts if not _in_any_network(h, networks)]
        if verbose and len(hosts) < before:
            print(f"[+] Filtered {before - len(hosts)} excluded host(s) out of discovery results")

    return hosts


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


def build_tcp_scan_cmd(hosts, tcp_ports=None, tcp_timing=None, pacing=None):
    """`pacing` (a list of nmap flags from a scan profile) replaces the
    legacy single `tcp_timing` value when given."""

    flags = list(pacing) if pacing is not None else [f"-{tcp_timing or 'T5'}"]

    return (
        ["nmap", "-n"] + flags +
        ["-p", tcp_ports or OT_TCP_PORTS, "-sT", "-oX", str(SCAN_XML)] +
        list(hosts)
    )


def build_udp_scan_cmd(hosts, udp_ports=None, udp_timing=None, pacing=None):
    flags = list(pacing) if pacing is not None else [f"-{udp_timing or 'T4'}"]

    return (
        ["nmap", "-n"] + flags +
        ["-sU", "-p", udp_ports or OT_UDP_PORTS, "-oX", str(UDP_SCAN_XML)] +
        list(hosts)
    )


def scan_live_hosts(hosts, verbose=False, udp=False, tcp_ports=None, udp_ports=None,
                     tcp_timing=None, udp_timing=None, pacing=None, udp_pacing=None):
    if not hosts:
        print("[-] No active hosts found.")
        return

    print(f"[+] Scanning {len(hosts)} hosts for OT ports...")

    cmd = build_tcp_scan_cmd(hosts, tcp_ports, tcp_timing, pacing)

    run_cmd(cmd, verbose, purpose="tcp_scan")

    print("[+] Targeted TCP scan complete.")

    if udp:
        scan_udp_ports(hosts, verbose, udp_ports=udp_ports, udp_timing=udp_timing,
                       pacing=udp_pacing)


def scan_udp_ports(hosts, verbose=False, udp_ports=None, udp_timing=None, pacing=None):
    print(f"[+] Scanning {len(hosts)} hosts for UDP OT ports (requires root)...")

    cmd = build_udp_scan_cmd(hosts, udp_ports, udp_timing, pacing)

    result = runner.run(cmd, purpose="udp_scan", capture_output=True, text=True)

    if result.returncode != 0:
        print("[-] UDP scan failed (likely needs sudo/root privileges). Skipping.")
        if verbose:
            print(result.stderr)
        return

    if verbose:
        print(result.stdout)

    print("[+] UDP scan complete.")