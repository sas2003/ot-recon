# ot_recon/core/netutils.py
#
# Detects the scanning machine's own IP address(es) so the discovery
# phase can exclude them by default - without this, every subnet scan
# that happens to include your own machine's address range reports your
# own PC as a discovered "asset" alongside the actual OT devices.

import re
import socket
import subprocess


def _ips_via_ip_command():
    """Linux: parse `ip -4 -o addr show` for every IPv4 address bound to
    a non-loopback interface. Covers multi-homed machines (multiple
    NICs/VLANs), which a single "what's my outbound IP" trick would miss."""

    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return set()

    if result.returncode != 0:
        return set()

    ips = set()
    for line in result.stdout.splitlines():
        if " lo " in line or line.strip().startswith("1:"):
            continue  # skip the loopback interface
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            ips.add(m.group(1))

    return ips


def _ip_via_outbound_socket():
    """Fallback for when `ip` isn't available (non-Linux, minimal
    containers). Doesn't actually send packets - opening a UDP socket and
    connecting just asks the OS which local address it would route
    through, which is enough to catch the common single-NIC case even if
    it can't enumerate every interface like _ips_via_ip_command() can."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            return {s.getsockname()[0]}
    except OSError:
        return set()


def get_local_ips():
    """Best-effort set of this machine's own IPv4 addresses, across all
    interfaces where possible. Never raises - returns an empty set if
    detection fails entirely, so callers can safely treat "no local IPs
    found" as "nothing to exclude" rather than crashing a scan over it."""

    ips = _ips_via_ip_command()

    if not ips:
        ips = _ip_via_outbound_socket()

    return ips
