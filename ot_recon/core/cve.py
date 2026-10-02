# ot_recon/core/cve.py
#
# Firmware/model/evidence-aware correlation against a small local CVE
# reference database (data/cve_db.yaml). Deliberately NOT a live feed —
# keeps the tool offline-friendly and avoids depending on network access
# or an API key just to run a scan.
#
# Design principle: only assert a *confirmed* hit when we can actually
# parse and compare firmware/version strings. When a rule needs a firmware
# check but we don't have (or can't parse) the firmware string, the
# finding is downgraded to "Info" and phrased as a possibility to verify,
# rather than presented with false confidence.

import re
import yaml

from ot_recon.core.paths import CVE_DB_YAML


def _load_db():
    try:
        with open(CVE_DB_YAML, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _parse_version(v):
    """Loosely extract a tuple of ints from a version-like string.
    Returns None if nothing numeric could be extracted."""

    if not v:
        return None

    nums = re.findall(r"\d+", str(v))

    if not nums:
        return None

    return tuple(int(n) for n in nums)


def _version_lt(current, threshold):
    """Return True/False if current < threshold, or None if not comparable
    (e.g. firmware string missing or non-numeric)."""

    c = _parse_version(current)
    t = _parse_version(threshold)

    if c is None or t is None:
        return None

    length = max(len(c), len(t))
    c = c + (0,) * (length - len(c))
    t = t + (0,) * (length - len(t))

    return c < t


def _vendor_key(vendor):
    if not vendor:
        return None

    v = vendor.lower()

    if "siemens" in v:
        return "siemens"

    if "b&r" in v:
        return "br"

    if "rockwell" in v or "allen-bradley" in v or "allen bradley" in v:
        return "rockwell"

    return None


def correlate(host):
    """Match a fingerprinted host against the known-CVE reference database.

    Returns a list of finding dicts:
        {"finding": str, "severity": str, "cve": str, "advisory": str|None}
    """

    db = _load_db()

    vendor_key = _vendor_key(host.get("vendor"))

    if vendor_key is None or vendor_key not in db:
        return []

    model = host.get("model") or ""
    firmware = host.get("firmware")
    evidence = host.get("evidence", [])
    open_ports = {
        p["port"] for p in host.get("ot_ports", []) if p["state"] == "open"
    }

    findings = []

    for entry in db[vendor_key]:

        match = entry.get("match", {})
        applies = True

        model_contains = match.get("model_contains")
        if model_contains:
            applies = applies and any(
                m.lower() in model.lower() for m in model_contains
            )

        requires_port = match.get("requires_port")
        if requires_port:
            applies = applies and requires_port in open_ports

        requires_evidence = match.get("requires_evidence")
        if requires_evidence:
            applies = applies and any(
                requires_evidence in e for e in evidence
            )

        # A rule with none of the above conditions is too broad to be
        # useful signal - skip it rather than firing on every host of a
        # vendor.
        if not (model_contains or requires_port or requires_evidence):
            applies = False

        if not applies:
            continue

        firmware_lt = match.get("firmware_lt")
        confirmed = True
        note = ""

        if firmware_lt:
            cmp_result = _version_lt(firmware, firmware_lt)

            if cmp_result is True:
                confirmed = True
            elif cmp_result is False:
                continue  # firmware >= patched version, not affected
            else:
                confirmed = False
                note = (
                    f" (firmware not read or unparsable — "
                    f"verify manually if < {firmware_lt})"
                )

        cve_ids = [entry["id"]] + entry.get("also", [])
        severity = entry["severity"] if confirmed else "Info"

        priority_map = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Info": "P5"}
        advisory_url = entry.get("advisory")

        if confirmed:
            if firmware_lt:
                recommendation = (
                    f"Upgrade firmware to version {firmware_lt} or newer according to "
                    f"vendor advisory ({advisory_url or 'vendor PSIRT'})."
                )
            elif advisory_url:
                recommendation = f"Review vendor security advisory ({advisory_url}) and apply recommended mitigations."
            else:
                recommendation = "Apply vendor security patch or isolate affected controller from untrusted subnets."
            likelihood = "High" if (requires_port and requires_port in open_ports) else "Medium"
        else:
            recommendation = (
                f"Verify installed firmware version manually against vendor threshold (< {firmware_lt}); "
                f"apply patch if vulnerable."
            )
            likelihood = "Low"

        related_ports = [requires_port] if requires_port else []

        findings.append({
            "finding": f"{entry['title']}{note}",
            "severity": severity,
            "cve": ", ".join(cve_ids),
            "advisory": advisory_url,
            "impact": entry.get("severity", "Medium"),
            "likelihood": likelihood,
            "recommendation": recommendation,
            "remediation_priority": priority_map.get(severity, "P4"),
            "related_ports": related_ports,
        })

    return findings
