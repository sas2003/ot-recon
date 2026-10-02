import subprocess
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ot_recon.core.paths import DATA_DIR

# Fingerprinting is I/O/subprocess-bound (nmap scripts + HTTP probes), so a
# thread pool is the right concurrency tool here - no need for
# multiprocessing overhead. Cap the default so we don't spawn an
# unreasonable number of concurrent nmap processes on large subnets.
DEFAULT_WORKERS = 10

# Path to the custom B&R NSE script shipped with this project.
BR_NSE_SCRIPT = str(DATA_DIR / "nse" / "br-info.nse")

_print_lock = threading.Lock()


def _log(msg):
    with _print_lock:
        print(msg)


def _fingerprint_host(host, verbose=False, script_timeout=30):

    host["evidence"] = []
    host["vendor"] = None
    host["model"] = None
    host["firmware"] = None
    host["fingerprint_method"] = "none"

    ip = host["ip"]

    protocols = [
        p["protocol"]
        for p in host.get("ot_ports", [])
        if p.get("state", "open") == "open"
    ]

    #
    # Siemens Controller
    #
    # Any successful s7-info response is itself PLC confirmation — S7comm
    # (port 102) only ever runs on PLC/CPU hardware, so the presence of
    # an S7 response IS the evidence.  We no longer look for a literal
    # "Module Type: PLC" string (that field contains the hardware model
    # name like "CPU 315-2 DP", not the word "PLC").
    #
    if "S7" in protocols:

        try:

            result = subprocess.run(
                [
                    "nmap",
                    "-n",
                    ip,
                    "-p", "102",
                    "-sV",
                    "--script", "s7-info"
                ],
                capture_output=True,
                text=True,
                timeout=script_timeout
            )

            output = result.stdout

            if "Siemens" in output:
                host["vendor"] = "Siemens"
                host["fingerprint_method"] = "nse_script"

            module = re.search(r"Module:\s*(.+)", output)
            if module:
                host["model"] = module.group(1).strip()

            version = re.search(r"Version:\s*(.+)", output)
            if version:
                host["firmware"] = version.group(1).strip()

            # Any s7-info response with identifiable content = PLC
            # confirmation. S7comm is PLC-only traffic by definition.
            module_type = re.search(r"Module Type:\s*(.+)", output)
            if module_type:
                host["evidence"].append(
                    f"S7 Module Type: {module_type.group(1).strip()}"
                )

            # Capture additional fields the real script provides.
            basic_hw = re.search(r"Basic Hardware:\s*(.+)", output)
            if basic_hw:
                host["evidence"].append(
                    f"Basic Hardware: {basic_hw.group(1).strip()}"
                )

            serial = re.search(r"Serial Number:\s*(.+)", output)
            if serial:
                host["evidence"].append(
                    f"Serial Number: {serial.group(1).strip()}"
                )

            system_name = re.search(
                r"System Name:\s*(.+)",
                output
            )

            if system_name:
                host["evidence"].append(
                    f"System Name: {system_name.group(1).strip()}"
                )

            # If we got any meaningful s7-info fields back, this is
            # definitively a PLC (S7comm is PLC-only by protocol spec).
            if module_type or module or host["vendor"] == "Siemens":
                host["evidence"].append(
                    "S7comm response confirmed (PLC/CPU)"
                )

        except Exception as e:
            if verbose:
                _log(f"[-] {ip}: S7 fingerprint failed ({e})")

    #
    # Siemens Panel
    #
    if "HTTP" in protocols:

        try:

            result = subprocess.run(
                [
                    "nmap",
                    "-n",
                    ip,
                    "-p", "80,443",
                    "-sV",
                    "--script",
                    "http-title,ssl-cert"
                ],
                capture_output=True,
                text=True,
                timeout=script_timeout
            )

            output = result.stdout

            if "SIMATIC HMI" in output:

                host["vendor"] = "Siemens"
                host["fingerprint_method"] = "nse_script"

                host["evidence"].append(
                    "SIMATIC HMI"
                )

            title = re.search(
                r"http-title:\s*(.+)",
                output
            )

            if title:
                host["evidence"].append(
                    f"Title: {title.group(1).strip()}"
                )

        except Exception as e:
            if verbose:
                _log(f"[-] {ip}: HTTP fingerprint failed ({e})")

    #
    # Rockwell EtherNet/IP
    #
    if "EtherNet/IP" in protocols:

        try:

            result = subprocess.run(
                [
                    "nmap",
                    "-n",
                    ip,
                    "-p", "44818",
                    "--script",
                    "enip-info"
                ],
                capture_output=True,
                text=True,
                timeout=script_timeout
            )

            output = result.stdout

            vendor = re.search(
                r"vendor:\s*(.+)",
                output
            )

            if vendor:
                host["vendor"] = vendor.group(1).strip()
                host["fingerprint_method"] = "nse_script"

            product = re.search(
                r"productName:\s*(.+)",
                output
            )

            if product:
                host["model"] = product.group(1).strip()

            revision = re.search(
                r"revision:\s*(.+)",
                output
            )

            if revision:
                host["firmware"] = revision.group(1).strip()

            device_type = re.search(
                r"type:\s*(.+)",
                output
            )

            if device_type:

                host["evidence"].append(
                    f"Device Type: {device_type.group(1).strip()}"
                )

        except Exception as e:
            if verbose:
                _log(f"[-] {ip}: EtherNet/IP fingerprint failed ({e})")

    #
    # B&R Automation
    #
    # Migrated from ad-hoc Python requests-based HTTP probing to a proper
    # custom Nmap NSE script (data/nse/br-info.nse), for architectural
    # consistency with Siemens (s7-info) and Rockwell (enip-info).
    #
    # The NSE script probes SDM/mapp View/mapp Cockpit web endpoints.
    # Raw PVI/ANSL/SafeDESIGNER ports are still handled via port-signature
    # evidence only (no public protocol spec exists).
    #
    br_ports = {p["port"] for p in host.get("ot_ports", []) if p.get("state", "open") == "open"}
    br_signature_ports = {11159, 11160, 11169, 50000, 51000, 8084, 81}
    br_http_ports = br_ports & {80, 81, 8084}

    if br_ports & br_signature_ports or "HTTP" in protocols:

        br_confirmed = False

        # --- NSE-based confirmation (replaces old requests-based probe) ---
        if br_http_ports or "HTTP" in protocols:

            scan_ports = ",".join(str(p) for p in sorted(
                br_http_ports | ({80} if "HTTP" in protocols else set())
            ))

            try:
                result = subprocess.run(
                    [
                        "nmap",
                        "-n",
                        ip,
                        "-p", scan_ports,
                        "--script", BR_NSE_SCRIPT,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=script_timeout,
                )

                output = result.stdout

                # Parse br-info NSE output:
                #   Vendor: B&R Automation
                #   Component: System Diagnostics Manager (SDM) on port 80
                #   Title (/sdm): System Diagnostics Manager
                if "Vendor: B&R" in output:
                    host["vendor"] = "B&R Automation"
                    host["fingerprint_method"] = "nse_script"
                    br_confirmed = True

                component = re.search(
                    r"Component:\s*(.+)", output
                )
                if component:
                    host["evidence"].append(component.group(1).strip())
                    host["fingerprint_method"] = "nse_script"
                    br_confirmed = True

                title = re.search(
                    r"Title\s*\([^)]*\):\s*(.+)", output
                )
                if title:
                    host["evidence"].append(
                        f"BR-Info Title: {title.group(1).strip()}"
                    )

            except Exception as e:
                if verbose:
                    _log(f"[-] {ip}: B&R NSE probe failed ({e})")

        # --- Port-signature fallback evidence ---
        port_signatures = {
            11169: "B&R Automation Studio/ANSL port open (11169)",
            11159: "B&R PVI legacy port open (11159)",
            11160: "B&R PVI fast-transfer port open (11160)",
            50000: "B&R SafeDESIGNER port open (50000)",
            51000: "B&R SafeDESIGNER secondary port open (51000)",
            8084: "B&R mapp Cockpit port open (8084)",
        }

        for port_num, desc in port_signatures.items():
            if port_num in br_ports:
                host["evidence"].append(desc)
                if not br_confirmed and host.get("vendor") is None:
                    host["vendor"] = "B&R Automation (unconfirmed - port signature only)"
                    host["fingerprint_method"] = "port_signature"

    return host


def fingerprint(data, verbose=False, workers=DEFAULT_WORKERS, script_timeout=30):

    if not data:
        return data

    total = len(data)
    print(f"[+] Fingerprinting {total} asset(s) with {min(workers, total)} worker(s)...")

    done = 0

    # Submit all hosts to the pool and update each host dict in place as
    # results land - order of completion doesn't matter since each host is
    # independent and `data` holds references, not copies.
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:

        future_to_host = {
            executor.submit(_fingerprint_host, host, verbose, script_timeout): host
            for host in data
        }

        for future in as_completed(future_to_host):
            host = future_to_host[future]

            try:
                future.result()
            except Exception as e:
                if verbose:
                    _log(f"[-] {host.get('ip', '?')}: fingerprinting crashed ({e})")

            done += 1
            _log(f"[+] Fingerprinted {done}/{total} ({host.get('ip', '?')})")

    return data
