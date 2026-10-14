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
from ot_recon.core import nvd_client, cve_cache


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


def _set_status(host, which, **status):
    """Record what the CVE stage did for this host ("local" / "live"), so
    the coverage report can say 'not checked' instead of implying 'clean'."""
    host.setdefault("cve_status", {})[which] = status


def _correlate_local(host):
    """Match a fingerprinted host against the hand-curated local CVE
    reference database (data/cve_db.yaml). Always runs, regardless of
    live-lookup settings - this is the guaranteed offline baseline.

    Returns a list of finding dicts:
        {"finding": str, "severity": str, "cve": str, "advisory": str|None, ...}
    """

    db = _load_db()

    vendor_key = _vendor_key(host.get("vendor"))

    if vendor_key is None or vendor_key not in db:
        _set_status(host, "local", state="skipped",
                    reason="vendor not identified" if not host.get("vendor")
                    else "no local CVE rules for this vendor")
        return []

    model = host.get("model") or ""
    firmware = host.get("firmware")
    evidence = host.get("evidence", [])
    open_ports = {
        p["port"] for p in host.get("ot_ports", []) if p["state"] == "open"
    }

    findings = []

    # Build comprehensive search space from model and all evidence strings
    model_clues = [model] + [str(e) for e in evidence]
    model_search_space = " ".join(model_clues).lower()
    if "6es7 5" in model_search_space or "6es75" in model_search_space or "6es7-5" in model_search_space:
        model_search_space += " s7-1500 1500"
    elif "6es7 2" in model_search_space or "6es72" in model_search_space or "6es7-2" in model_search_space:
        model_search_space += " s7-1200 1200"
    elif "6es7 3" in model_search_space or "6es73" in model_search_space or "6es7-3" in model_search_space:
        model_search_space += " s7-300 300"
    elif "6es7 4" in model_search_space or "6es74" in model_search_space or "6es7-4" in model_search_space:
        model_search_space += " s7-400 400"

    for entry in db[vendor_key]:

        match = entry.get("match", {})
        applies = True

        model_contains = match.get("model_contains")
        if model_contains:
            applies = applies and any(
                m.lower() in model_search_space for m in model_contains
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
        # How this finding was established (see risk.DETECTION_LEVELS):
        #   product_matched - product identified; advisory not version-gated
        #   version_matched - product AND firmware identified, firmware affected
        #   inconclusive    - product matches but firmware unknown
        detection = "product_matched"

        if firmware_lt:
            cmp_result = _version_lt(firmware, firmware_lt)

            if cmp_result is True:
                confirmed = True
                detection = "version_matched"
            elif cmp_result is False:
                continue  # firmware >= patched version, not affected
            else:
                confirmed = False
                detection = "inconclusive"
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
            "source": "local_db",
            "detection": detection,
        })

    _set_status(host, "local", state="evaluated", rules=len(db[vendor_key]),
                matched=len(findings))
    return findings


def _collect_known_cve_ids(findings):
    ids = set()
    for f in findings:
        for cid in (f.get("cve") or "").split(","):
            cid = cid.strip()
            if cid:
                ids.add(cid)
    return ids


_PRIORITY_MAP = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Info": "P5"}


def _correlate_live(host, cve_config, known_cve_ids, verbose=False):
    """Supplement local findings with a live NVD lookup, cache-first.
    Never raises - any failure (no internet, timeout, bad response, rate
    limit) is caught and treated as "no live data this run"."""

    vendor = host.get("vendor")
    model = host.get("model")

    if not model and host.get("evidence"):
        for e in host["evidence"]:
            if "S7 Module Type:" in e:
                model = e.split(":", 1)[1].strip()
                break
            elif "System Name:" in e and any(k in e for k in ("S7-", "SIMATIC", "1500", "1200")):
                model = e.split(":", 1)[1].strip()
                break
            elif "Component:" in e:
                model = e.split(":", 1)[1].strip()
                break

    if not vendor or not model:
        _set_status(host, "live", state="skipped", reason="vendor/model not identified")
        return []  # nothing specific enough to search NVD for

    # Translate raw Siemens catalog numbers to indexed family keywords
    query_model = model
    m_lower = model.lower()
    if "6es7 5" in m_lower or "6es75" in m_lower or "6es7-5" in m_lower:
        query_model = f"S7-1500 {model}"
    elif "6es7 2" in m_lower or "6es72" in m_lower or "6es7-2" in m_lower:
        query_model = f"S7-1200 {model}"
    elif "6es7 3" in m_lower or "6es73" in m_lower or "6es7-3" in m_lower:
        query_model = f"S7-300 {model}"

    ttl_days = cve_config.get("cache_ttl_days", cve_cache.DEFAULT_TTL_DAYS)
    cached = cve_cache.get_cached(vendor, query_model, ttl_days=ttl_days)

    if cached is not None:
        raw_results = cached
        _set_status(host, "live", state="cache_hit", results=len(raw_results))
    else:
        try:
            raw_results = nvd_client.query_nvd(
                vendor, query_model,
                api_key=cve_config.get("api_key"),
                timeout=cve_config.get("request_timeout", 10),
            )
            cve_cache.set_cached(vendor, query_model, raw_results)
            _set_status(host, "live", state="queried", results=len(raw_results))
        except Exception as e:
            if verbose:
                print(f"[-] NVD live lookup failed for {vendor} {query_model}: {e}")
            _set_status(host, "live", state="failed", reason=str(e)[:150])
            return []

    findings = []

    for r in raw_results:
        if r["id"] in known_cve_ids:
            continue  # already covered by a curated local_db entry

        severity = r.get("severity") or "Medium"

        findings.append({
            "finding": f"{r['title']} (NVD live match, not firmware-verified)",
            "severity": severity,
            "cve": r["id"],
            "advisory": r.get("advisory"),
            "impact": severity,
            # Live matches are keyword+CPE cross-validated but never
            # firmware-range-gated the way local_db entries can be, so
            # likelihood stays conservative rather than mirroring severity.
            "likelihood": "Medium",
            "recommendation": (
                f"Review NVD entry for {r['id']} and the linked advisory; "
                f"verify applicability against the installed firmware version."
            ),
            "remediation_priority": _PRIORITY_MAP.get(severity, "P4"),
            "related_ports": [],
            "source": "nvd_live",
            "detection": "external_unverified",
        })

    return findings


def correlate(host, cve_config=None, verbose=False):
    """Match a fingerprinted host against the local CVE database, and -
    if cve_config enables it - supplement with a live NVD lookup.

    cve_config (optional): {"live_lookup": bool, "api_key": str|None,
    "cache_ttl_days": int, "request_timeout": int}. Local correlation
    always runs regardless; live lookup is strictly additive and fails
    silently back to local-only on any error.
    """

    local_findings = _correlate_local(host)

    if not cve_config or not cve_config.get("live_lookup"):
        _set_status(host, "live", state="disabled")
        return local_findings

    known_ids = _collect_known_cve_ids(local_findings)
    live_findings = _correlate_live(host, cve_config, known_ids, verbose=verbose)

    return local_findings + live_findings
