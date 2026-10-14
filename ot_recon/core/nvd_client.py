# ot_recon/core/nvd_client.py
#
# Optional live lookup against the NVD CVE API 2.0, used to supplement
# (never replace) the local curated CVE database in cve_db.yaml.
#
# Design principles:
#   - Opt-in only (cve.live_lookup in config), off by default. The tool
#     must work fully offline with zero behavior change if this is left
#     disabled or network/API access fails.
#   - No pre-built CPE table. Exact CPE strings are a maintenance trap
#     (Siemens alone has dozens of per-CPU-model firmware CPE slugs) - we
#     query NVD's keywordSearch instead, then cross-validate each
#     candidate CVE against its OWN embedded configurations[].nodes[]
#     .cpeMatch[].criteria list, checking the vendor + model tokens
#     actually appear in at least one CPE tied to that CVE. This gets
#     CPE-level precision without us having to know the exact CPE string
#     in advance.
#   - Any failure (no internet, timeout, 429, malformed response) is
#     caught, logged under --verbose, and treated as "no live data this
#     run" - never raises, never blocks a scan.
#   - requests is an optional dependency (extras_require["cve-live"]),
#     imported lazily so the rest of the tool never requires it.

import re
import time

try:
    import requests
except ImportError:
    requests = None

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's stated rate limits: 5 req/30s without a key, 50 req/30s with one.
# Pace requests to stay safely under whichever applies, rather than
# bursting and hitting a 429.
_last_request_at = {"t": 0.0}


def _pace(has_api_key):
    min_interval = 0.65 if has_api_key else 6.5  # a little under the limit, not right at it
    elapsed = time.time() - _last_request_at["t"]
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_request_at["t"] = time.time()


def _severity_from_cvss(cve_obj):
    """Pull baseScore/baseSeverity from whichever CVSS version NVD
    provided (v3.1 preferred, falling back to v3.0 then v2), and map to
    our Critical/High/Medium/Low scale."""

    metrics = cve_obj.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")

            if severity:
                severity = severity.title()
                if severity not in ("Critical", "High", "Medium", "Low"):
                    severity = None

            if severity is None and score is not None:
                # CVSS v2 responses don't carry baseSeverity - derive it.
                if score >= 9.0:
                    severity = "Critical"
                elif score >= 7.0:
                    severity = "High"
                elif score >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"

            return severity or "Medium", score

    return "Medium", None


def _extract_cpe_criteria(cve_obj):
    criteria = []
    for config in cve_obj.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                c = match.get("criteria")
                if c:
                    criteria.append((c, match))
    return criteria


def _vendor_matches_cpe(vendor_token, cpe_string):
    """Check if vendor_token matches the vendor in the CPE string,
    accounting for industrial vendor naming variants like
    'Rockwell Automation/Allen-Bradley' vs 'rockwellautomation'."""
    if not vendor_token:
        return True
    v = vendor_token.lower()
    c = cpe_string.lower()
    if v in c:
        return True
    if "rockwell" in v or "allen-bradley" in v:
        return "rockwell" in c or "allen-bradley" in c or "allen_bradley" in c
    if "siemens" in v:
        return "siemens" in c
    if "b&r" in v or "br automation" in v:
        return "br-automation" in c or "b&r" in c or "buchegger" in c
    tokens = [t for t in re.split(r"[\s/_-]+", v) if len(t) >= 4 and t not in ("automation", "corporation", "inc", "ltd")]
    return any(tok in c for tok in tokens) if tokens else False


def _vendor_model_match_cpe(criteria_list, vendor_token, model_tokens):
    """Does at least one CPE criteria string tied to this CVE mention our
    vendor and at least one meaningful model token? This is the
    cross-validation step that substitutes for needing an exact
    pre-built CPE string."""

    for criteria, _match in criteria_list:
        c = criteria.lower()
        if not _vendor_matches_cpe(vendor_token, c):
            continue
        if not model_tokens:
            return True
        if any(tok.lower() in c for tok in model_tokens if len(tok) >= 3):
            return True

    return False


def _model_tokens(model):
    """Split a model string like 'CompactLogix 5370' or 'SIMATIC S7-1500'
    into meaningful tokens to check against CPE criteria / descriptions,
    dropping short/generic words that would match too broadly."""

    if not model:
        return []

    STOPWORDS = {"cpu", "plc", "the", "and", "pn", "dp"}
    raw = re.split(r"[\s/_-]+", model)
    return [t for t in raw if len(t) >= 3 and t.lower() not in STOPWORDS]


def query_nvd(vendor, model, api_key=None, timeout=10, max_results=20):
    """Query NVD for CVEs plausibly affecting `vendor`/`model`, cross-
    validated against each candidate's own CPE configuration data.

    Returns a list of raw match dicts:
        {id, title, severity, cvss_score, advisory, cpe_criteria}
    or raises on failure (caller is expected to catch - see cve.py).
    """

    if requests is None:
        raise RuntimeError(
            "the 'requests' package is required for live NVD lookups - "
            "install with: pip install -e \".[cve-live]\""
        )

    keyword = f"{vendor} {model}".strip()
    if not keyword:
        return []

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    _pace(has_api_key=bool(api_key))

    resp = requests.get(
        NVD_BASE_URL,
        params={"keywordSearch": keyword, "resultsPerPage": max_results},
        headers=headers,
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()

    model_tokens = _model_tokens(model)
    results = []

    for item in data.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id")
        if not cve_id:
            continue

        criteria_list = _extract_cpe_criteria(cve_obj)

        # Cross-validation: only keep this CVE if its own CPE data (when
        # present) actually ties it to our vendor/model. If a CVE has no
        # CPE configuration data at all (common for very recent CVEs),
        # fall back to requiring the model token in the description text
        # instead of discarding it outright.
        descriptions = cve_obj.get("descriptions", [])
        description_text = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
        )

        if criteria_list:
            if not _vendor_model_match_cpe(criteria_list, vendor, model_tokens):
                continue
        elif model_tokens:
            if not any(tok.lower() in description_text.lower() for tok in model_tokens):
                continue

        severity, cvss_score = _severity_from_cvss(cve_obj)

        references = cve_obj.get("references", [])
        advisory = references[0]["url"] if references else None

        results.append({
            "id": cve_id,
            "title": description_text[:300] if description_text else cve_id,
            "severity": severity,
            "cvss_score": cvss_score,
            "advisory": advisory,
            "cpe_criteria": [c for c, _ in criteria_list],
        })

    return results
