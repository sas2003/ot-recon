# ot_recon/core/coverage.py
#
# Answers the question every scanner report quietly dodges: "what did you
# NOT check?". A report that lists findings but not gaps invites the
# reader to treat "no findings" as "safe" - in OT that is the dangerous
# conclusion, because a host we couldn't fingerprint, a protocol we have
# no probe for, or a firmware version we couldn't read all produce
# silence rather than an error.
#
# For every host this builds:
#   checks - what was attempted and how it went
#   gaps   - plain-language statements of what could NOT be assessed
#   status - full | partial | limited | n/a   (see build_host_coverage)
#
# and for the scan as a whole, scan-level gaps/notes (UDP not scanned,
# live CVE lookup off, protocols we have no probe for, exclusions).

from collections import Counter

# Protocols for which OT-Recon sends an identification probe.
PROBED_PROTOCOLS = {"S7", "EtherNet/IP"}      # HTTP/B&R handled via web probes

# OT protocols detected by port/service but never actively identified.
UNPROBED_OT_PROTOCOLS = {"Modbus", "DNP3", "OPC UA"}

BR_RAW_PORTS = {11159, 11160, 11169, 50000, 51000}

_PROBE_STATUS = {
    "data": ("completed", "returned identifying data"),
    "no_data": ("inconclusive", "device answered but returned no identifying data"),
    "timeout": ("failed", "timed out"),
    "error": ("failed", "probe failed"),
}


def _open(services):
    return [s for s in services if s.get("state", "open") == "open"]


def _ot_services(host):
    return [s for s in _open(host.get("services", [])) if s.get("category") == "ot"]


def build_host_coverage(host, scan_ctx=None):
    """Return {"status", "checks", "gaps"} for one host.

    status:
      n/a      no OT services on this host - OT checks don't apply
      limited  OT services present but nothing authoritative was learned
               (no probe returned data, vendor unknown)
      partial  assessed, but with one or more gaps listed
      full     assessed with no gaps
    """

    checks, gaps = [], []
    ot_services = _ot_services(host)
    ot_protocols = sorted({s.get("protocol") for s in ot_services if s.get("protocol")})
    findings = host.get("risks", [])
    vendor = host.get("vendor")
    open_ports = {s["port"] for s in _open(host.get("services", []))} or {
        p["port"] for p in _open(host.get("ot_ports", []))
    }

    checks.append({
        "check": "Service enumeration (TCP)",
        "status": "completed",
        "detail": f"{len(_open(host.get('services', [])) or _open(host.get('ot_ports', [])))} open service(s) found",
    })

    # --- fingerprint probes ---------------------------------------------------
    probes = host.get("probes", [])
    probe_data = False
    for p in probes:
        status, detail = _PROBE_STATUS.get(p.get("status"), ("failed", "unknown outcome"))
        if p.get("status") == "data":
            probe_data = True
        if p.get("error"):
            detail = f"{detail}: {p['error']}"
        checks.append({"check": f"Fingerprint probe: {p['probe']}", "status": status, "detail": detail})
        if status != "completed":
            gaps.append(f"{p['probe']} probe {detail} - device identity from this probe is unconfirmed.")

    # --- identification -------------------------------------------------------
    confirmed_vendor = bool(vendor) and "unconfirmed" not in vendor

    if ot_services and not vendor:
        gaps.append(
            f"OT service(s) present ({', '.join(ot_protocols)}) but the device could not be "
            f"fingerprinted - vendor and model are unknown, so vendor-specific checks did not run."
        )
    elif vendor and not confirmed_vendor:
        gaps.append("Vendor inferred from port numbers only - not confirmed by any probe response.")

    inconclusive = [f for f in findings if f.get("detection") == "inconclusive"]
    if vendor and not host.get("firmware"):
        if inconclusive:
            gaps.append(
                f"Firmware version could not be read - {len(inconclusive)} vulnerability check(s) "
                f"are inconclusive and need manual verification."
            )
        checks.append({"check": "Firmware identification", "status": "inconclusive",
                       "detail": "firmware version not read"})
    elif host.get("firmware"):
        checks.append({"check": "Firmware identification", "status": "completed",
                       "detail": f"firmware {host['firmware']}"})

    # --- protocols with no identification probe -------------------------------
    for proto in ot_protocols:
        if proto in UNPROBED_OT_PROTOCOLS:
            gaps.append(
                f"{proto} detected, but OT-Recon has no read-only identification probe for it - "
                f"device identity and configuration were not verified."
            )

    br_raw = sorted(open_ports & BR_RAW_PORTS)
    if br_raw:
        gaps.append(
            f"B&R engineering port(s) {', '.join(map(str, br_raw))} identified by port number only; "
            f"the proprietary protocol was not probed (no public specification)."
        )

    # --- classification -------------------------------------------------------
    if ot_services and host.get("type") not in (None, "Unknown") and not host.get("evidence_based"):
        gaps.append("Device type inferred from protocol heuristics, not confirmed by probe evidence.")

    # --- CVE stages -----------------------------------------------------------
    cve_status = host.get("cve_status", {})
    local = cve_status.get("local")
    if local:
        if local.get("state") == "evaluated":
            checks.append({"check": "CVE correlation (local database)", "status": "completed",
                           "detail": f"{local.get('rules', 0)} rule(s) evaluated, {local.get('matched', 0)} matched"})
        elif ot_services:
            gaps.append(f"CVE correlation did not run for this host: {local.get('reason', 'skipped')}.")
            checks.append({"check": "CVE correlation (local database)", "status": "skipped",
                           "detail": local.get("reason", "skipped")})

    live = cve_status.get("live")
    if live and live.get("state") in ("queried", "cache_hit"):
        checks.append({"check": "CVE correlation (live NVD)", "status": "completed",
                       "detail": f"{live['state'].replace('_', ' ')}, {live.get('results', 0)} candidate(s)"})
    elif live and live.get("state") == "failed":
        gaps.append(f"Live NVD lookup failed ({live.get('reason', 'unknown')}) - only the local database was used.")
        checks.append({"check": "CVE correlation (live NVD)", "status": "failed", "detail": live.get("reason", "")})
    elif live and live.get("state") == "skipped" and ot_services:
        gaps.append(f"Live NVD lookup skipped: {live.get('reason', 'insufficient identification')}.")

    # --- overall status -------------------------------------------------------
    if not ot_services and not vendor:
        status = "n/a"
    elif not probe_data and not confirmed_vendor:
        status = "limited"
    elif gaps:
        status = "partial"
    else:
        status = "full"

    return {"status": status, "checks": checks, "gaps": gaps}


def build_scan_coverage(data, scan_ctx):
    """Scan-wide gaps (things the operator should know weren't covered)
    and neutral notes (context that isn't a deficiency)."""

    gaps, notes = [], []

    if not scan_ctx.get("udp_scanned"):
        gaps.append(
            "UDP was not scanned: EtherNet/IP implicit I/O (2222) and SNMP (161) over UDP were not "
            "assessed. Re-run with --udp (requires root) to cover them."
        )

    if not scan_ctx.get("cve_live"):
        gaps.append(
            "Live NVD lookup was off: vulnerability data comes only from the curated local database, "
            "so recently published CVEs may be missing. Enable with --cve-live."
        )

    proto_hosts = Counter()
    for h in data:
        for proto in {s.get("protocol") for s in _ot_services(h)}:
            if proto in UNPROBED_OT_PROTOCOLS:
                proto_hosts[proto] += 1
    for proto, n in sorted(proto_hosts.items()):
        gaps.append(f"{proto} found on {n} host(s) but not actively identified (no probe implemented).")

    failed = sum(1 for h in data for p in h.get("probes", []) if p.get("status") in ("timeout", "error"))
    if failed:
        gaps.append(f"{failed} fingerprint probe(s) timed out or errored - see per-host coverage.")

    profile = (scan_ctx.get("profile") or {}).get("name")
    if profile == "safe":
        notes.append(
            "Scanned with the 'safe' profile: polite timing and minimal service-detection probing. "
            "This lowers risk to fragile devices at the cost of speed and some detail."
        )
    notes.append(
        "Only non-intrusive checks were performed: no exploits, no authentication attempts, "
        "no configuration changes, no write operations."
    )

    excluded = scan_ctx.get("excluded") or []
    if excluded:
        notes.append(f"Excluded from scanning by policy: {', '.join(excluded)}.")

    return {"gaps": gaps, "notes": notes}


def annotate(data, scan_ctx):
    """Attach host["coverage"] to every host and scan_ctx["coverage"] with
    scan-level gaps plus per-status host counts. Returns data."""

    counts = Counter()
    for host in data:
        host["coverage"] = build_host_coverage(host, scan_ctx)
        counts[host["coverage"]["status"]] += 1

    scan_cov = build_scan_coverage(data, scan_ctx)
    scan_cov["host_status_counts"] = {
        s: counts.get(s, 0) for s in ("full", "partial", "limited", "n/a")
    }
    scan_ctx["coverage"] = scan_cov
    return data
