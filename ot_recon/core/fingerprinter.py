import subprocess
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ot_recon.core.paths import DATA_DIR
from ot_recon.core import runner

# Fingerprinting is I/O/subprocess-bound (nmap scripts + HTTP probes), so a
# thread pool is the right concurrency tool here - no need for
# multiprocessing overhead. Cap the default so we don't spawn an
# unreasonable number of concurrent nmap processes on large subnets.
DEFAULT_WORKERS = 10

# Path to the custom B&R NSE script shipped with this project.
BR_NSE_SCRIPT = str(DATA_DIR / "nse" / "br-info.nse")

_print_lock = threading.Lock()

# Raw probe output kept as evidence is capped so snapshots/reports stay small.
MAX_EVIDENCE_CHARS = 4000


def _log(msg):
    with _print_lock:
        print(msg)


# Every active probe the tool can send, in one place. Shared by the real
# run and by --dry-run, so the plan shown to the operator is exactly what
# would execute. "version_detect" probes use nmap -sV (service detection).
PROBES = {
    "s7-info": {
        "ports": "102", "scripts": "s7-info", "version_detect": True,
        "applies": "an S7 service was found on port 102",
    },
    "http-title": {
        "ports": "80,443", "scripts": "http-title,ssl-cert", "version_detect": True,
        "applies": "an HTTP service was found",
    },
    "enip-info": {
        "ports": "44818", "scripts": "enip-info", "version_detect": False,
        "applies": "an EtherNet/IP service was found on port 44818",
    },
    "br-info": {
        "ports": "80,81,8084", "scripts": BR_NSE_SCRIPT, "version_detect": False,
        "applies": "an HTTP / B&R web service (80, 81, 8084) was found",
    },
}


def build_probe_cmd(name, ip, ports=None, pacing=None, version_intensity=None):
    """The exact nmap command for one probe.

    -Pn: discovery already proved the host is alive this run, so each probe
    skips nmap's own host-discovery step rather than sending redundant
    packets to a possibly fragile device before every probe."""

    spec = PROBES[name]
    cmd = ["nmap", "-n", "-Pn", ip] + list(pacing or []) + ["-p", ports or spec["ports"]]

    if spec["version_detect"]:
        cmd.append("-sV")
        if version_intensity is not None:
            cmd += ["--version-intensity", str(version_intensity)]

    cmd += ["--script", spec["scripts"]]
    return cmd


def _script_produced_data(output):
    # nmap prints NSE script results as lines starting with "|" / "|_".
    return any(line.startswith("|") for line in (output or "").splitlines())


def _run_probe(host, name, cmd, timeout, verbose, ports=""):
    """Run one probe through the audited runner and record exactly what
    happened on host["probes"] (the evidence trail the report shows).

    Returns the probe's stdout, or "" if it failed - callers then simply
    find nothing to parse, exactly as before. Never raises."""

    record = {
        "probe": name,
        "ports": ports,
        "command": " ".join(str(c) for c in cmd),
        "status": "error",
        "returncode": None,
        "duration_s": None,
        "output": "",
        "error": None,
    }
    started = time.time()
    output = ""

    try:
        result = runner.run(cmd, purpose=f"fingerprint:{name}",
                            capture_output=True, text=True, timeout=timeout)
        output = result.stdout or ""
        rc = result.returncode if isinstance(result.returncode, int) else 0
        record["returncode"] = rc

        if rc != 0:
            record["status"] = "error"
            record["error"] = (getattr(result, "stderr", "") or f"nmap exited with status {rc}").strip()[:300]
        elif _script_produced_data(output):
            record["status"] = "data"
        else:
            record["status"] = "no_data"

    except subprocess.TimeoutExpired:
        record["status"] = "timeout"
        record["error"] = f"no result within {timeout}s"
        if verbose:
            _log(f"[-] {host['ip']}: {name} probe timed out after {timeout}s")
    except Exception as e:
        record["status"] = "error"
        record["error"] = str(e)[:300]
        if verbose:
            _log(f"[-] {host['ip']}: {name} probe failed ({e})")

    record["duration_s"] = round(time.time() - started, 2)
    record["output"] = output[:MAX_EVIDENCE_CHARS]
    if len(output) > MAX_EVIDENCE_CHARS:
        record["output"] += "\n[... truncated ...]"

    host.setdefault("probes", []).append(record)
    return output


def _fingerprint_host(host, verbose=False, script_timeout=30, pacing=None,
                      version_intensity=None):

    host["evidence"] = []
    host["probes"] = []
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

            output = _run_probe(
                host, "s7-info",
                build_probe_cmd("s7-info", ip, pacing=pacing, version_intensity=version_intensity),
                script_timeout, verbose, ports="102",
            )

            if "Siemens" in output or "SIMATIC" in output or "6ES7" in output:
                host["vendor"] = "Siemens"
                host["fingerprint_method"] = "nse_script"

            module = re.search(r"Module:\s*(.+)", output, re.IGNORECASE)
            if module:
                host["model"] = module.group(1).strip()

            version = re.search(r"Version:\s*(.+)", output, re.IGNORECASE)
            if version:
                host["firmware"] = version.group(1).strip()

            # Any s7-info response with identifiable content = PLC
            # confirmation. S7comm is PLC-only traffic by definition.
            module_type = re.search(r"Module Type:\s*(.+)", output, re.IGNORECASE)
            if module_type:
                mtype_str = module_type.group(1).strip()
                host["evidence"].append(
                    f"S7 Module Type: {mtype_str}"
                )
                if not host.get("model"):
                    host["model"] = mtype_str

            # Capture additional fields the real script provides.
            basic_hw = re.search(r"Basic Hardware:\s*(.+)", output, re.IGNORECASE)
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

            output = _run_probe(
                host, "http-title",
                build_probe_cmd("http-title", ip, pacing=pacing, version_intensity=version_intensity),
                script_timeout, verbose, ports="80,443",
            )

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

            output = _run_probe(
                host, "enip-info",
                build_probe_cmd("enip-info", ip, pacing=pacing),
                script_timeout, verbose, ports="44818",
            )

            vendor = re.search(
                r"vendor:\s*(.+)",
                output,
                re.IGNORECASE,
            )

            if vendor:
                host["vendor"] = vendor.group(1).strip()
                host["fingerprint_method"] = "nse_script"

            product = re.search(
                r"(?:productName|product\s*name):\s*(.+)",
                output,
                re.IGNORECASE,
            )

            if product:
                host["model"] = product.group(1).strip()

            revision = re.search(
                r"revision:\s*(.+)",
                output,
                re.IGNORECASE,
            )

            if revision:
                host["firmware"] = revision.group(1).strip()

            device_type = re.search(
                r"(?:device\s*type|type):\s*(.+)",
                output,
                re.IGNORECASE,
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
                output = _run_probe(
                    host, "br-info",
                    build_probe_cmd("br-info", ip, ports=scan_ports, pacing=pacing),
                    script_timeout, verbose, ports=scan_ports,
                )

                # Parse br-info NSE output:
                #   Vendor: B&R Automation
                #   Component: System Diagnostics Manager (SDM) on port 80
                #   Title (/sdm): System Diagnostics Manager
                if "Vendor: B&R" in output:
                    host["vendor"] = "B&R Automation"
                    host["fingerprint_method"] = "nse_script"
                    br_confirmed = True

                component = re.search(
                    r"Component:\s*(.+)", output, re.IGNORECASE
                )
                if component:
                    cname = component.group(1).strip()
                    host["evidence"].append(cname)
                    host["fingerprint_method"] = "nse_script"
                    br_confirmed = True
                    if not host.get("model"):
                        host["model"] = cname

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


def fingerprint(data, verbose=False, workers=DEFAULT_WORKERS, script_timeout=30,
                pacing=None, version_intensity=None):

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
            executor.submit(_fingerprint_host, host, verbose, script_timeout,
                            pacing=pacing, version_intensity=version_intensity): host
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
