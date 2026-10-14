import yaml
import pytest
from unittest.mock import patch

from ot_recon.core import cve as cve_module


# --- version parsing / comparison helpers ---

@pytest.mark.parametrize("v,expected", [
    ("1.5.0", (1, 5, 0)),
    ("V2.9.3", (2, 9, 3)),
    ("33.011", (33, 11)),
    ("", None),
    (None, None),
    ("no-numbers-here", None),
])
def test_parse_version(v, expected):
    assert cve_module._parse_version(v) == expected


@pytest.mark.parametrize("current,threshold,expected", [
    ("1.2.0", "1.5.0", True),
    ("1.5.0", "1.5.0", False),
    ("2.0.0", "1.5.0", False),
    ("4", "4.0", False),        # padded comparison: (4,0) == (4,0)
    ("3", "4.0", True),
    (None, "1.5.0", None),      # unparsable current -> not comparable
    ("1.5.0", None, None),
])
def test_version_lt(current, threshold, expected):
    assert cve_module._version_lt(current, threshold) is expected


@pytest.mark.parametrize("vendor,expected_key", [
    ("Siemens", "siemens"),
    ("B&R Automation", "br"),
    ("B&R Automation (unconfirmed - port signature only)", "br"),
    ("Rockwell Automation/Allen-Bradley", "rockwell"),
    ("Some Other Vendor", None),
    (None, None),
    ("", None),
])
def test_vendor_key(vendor, expected_key):
    assert cve_module._vendor_key(vendor) == expected_key


# --- correlate() against an isolated, temporary test DB ---

TEST_DB = {
    "siemens": [
        {
            "id": "TEST-CVE-1",
            "title": "Test S7-1500 issue",
            "match": {"model_contains": ["S7-1500"], "firmware_lt": "1.5.0"},
            "severity": "High",
            "advisory": "https://example.com/test-cve-1",
        },
    ],
    "br": [
        {
            "id": "TEST-CVE-2",
            "title": "Test SNMP issue",
            "match": {"requires_port": 161},
            "severity": "Critical",
            "advisory": None,
        },
        {
            "id": "TEST-CVE-3",
            "title": "Test SDM issue",
            "match": {"requires_evidence": "System Diagnostics Manager", "firmware_lt": "6.4"},
            "severity": "High",
            "advisory": None,
        },
    ],
}


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_cve_db.yaml"
    with open(db_path, "w") as f:
        yaml.safe_dump(TEST_DB, f)

    monkeypatch.setattr(cve_module, "CVE_DB_YAML", db_path)
    return db_path


def test_confirmed_match_below_firmware_threshold(isolated_db):
    host = {
        "vendor": "Siemens",
        "model": "S7-1500",
        "firmware": "1.2.0",
        "evidence": [],
        "ot_ports": [],
    }

    findings = cve_module.correlate(host)

    assert len(findings) == 1
    assert findings[0]["severity"] == "High"
    assert findings[0]["cve"] == "TEST-CVE-1"


def test_no_match_when_firmware_patched(isolated_db):
    host = {
        "vendor": "Siemens",
        "model": "S7-1500",
        "firmware": "2.0.0",  # >= 1.5.0 threshold -> patched
        "evidence": [],
        "ot_ports": [],
    }

    findings = cve_module.correlate(host)
    assert findings == []


def test_unparsable_firmware_downgrades_to_info(isolated_db):
    host = {
        "vendor": "Siemens",
        "model": "S7-1500",
        "firmware": None,  # can't confirm nor rule out
        "evidence": [],
        "ot_ports": [],
    }

    findings = cve_module.correlate(host)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Info"
    assert "verify manually" in findings[0]["finding"]


def test_model_mismatch_produces_no_finding(isolated_db):
    host = {
        "vendor": "Siemens",
        "model": "S7-1200",  # rule only applies to S7-1500
        "firmware": "1.0.0",
        "evidence": [],
        "ot_ports": [],
    }

    findings = cve_module.correlate(host)
    assert findings == []


def test_requires_port_gating(isolated_db):
    host_with_port = {
        "vendor": "B&R Automation", "model": None, "firmware": None,
        "evidence": [], "ot_ports": [{"port": 161, "state": "open"}],
    }
    host_without_port = {
        "vendor": "B&R Automation", "model": None, "firmware": None,
        "evidence": [], "ot_ports": [],
    }

    assert any(f["cve"] == "TEST-CVE-2" for f in cve_module.correlate(host_with_port))
    assert not any(f["cve"] == "TEST-CVE-2" for f in cve_module.correlate(host_without_port))


def test_requires_evidence_gating(isolated_db):
    host = {
        "vendor": "B&R Automation", "model": None, "firmware": "6.0",
        "evidence": ["System Diagnostics Manager (SDM) confirmed on port 80"],
        "ot_ports": [],
    }

    findings = cve_module.correlate(host)
    assert any(f["cve"] == "TEST-CVE-3" for f in findings)


def test_unknown_vendor_returns_no_findings(isolated_db):
    host = {"vendor": "Acme Corp", "model": None, "firmware": None, "evidence": [], "ot_ports": []}
    assert cve_module.correlate(host) == []


def test_missing_vendor_returns_no_findings(isolated_db):
    host = {"vendor": None, "model": None, "firmware": None, "evidence": [], "ot_ports": []}
    assert cve_module.correlate(host) == []


# --- sanity check against the real shipped DB ---

def test_real_db_loads_and_parses():
    """The actual shipped data/cve_db.yaml should load without error and
    have entries for all 3 vendors."""

    db = cve_module._load_db()

    assert "siemens" in db
    assert "rockwell" in db
    assert "br" in db
    assert len(db["siemens"]) > 0
    assert len(db["rockwell"]) > 0
    assert len(db["br"]) > 0


def test_cve_findings_include_remediation_metadata(isolated_db):
    host = {
        "vendor": "Siemens",
        "model": "S7-1500",
        "firmware": "1.2.0",
        "evidence": [],
        "ot_ports": [],
    }

    findings = cve_module.correlate(host)
    assert len(findings) == 1
    f = findings[0]

    assert "impact" in f
    assert "likelihood" in f
    assert "recommendation" in f and "Upgrade firmware" in f["recommendation"]
    assert f["remediation_priority"] == "P2"
    assert "related_ports" in f


# --- correlate() with live NVD lookup (cve_config) ---

def test_live_lookup_disabled_by_default_returns_only_local(isolated_db):
    """No cve_config at all, and cve_config without live_lookup=True, must
    both behave identically to the pre-live-lookup local-only path - this
    is the backward-compatibility guarantee."""

    host = {
        "vendor": "Siemens", "model": "S7-1500", "firmware": "1.2.0",
        "evidence": [], "ot_ports": [],
    }

    with patch.object(cve_module, "nvd_client") as mock_nvd:
        findings_no_config = cve_module.correlate(host)
        findings_disabled = cve_module.correlate(host, cve_config={"live_lookup": False})

    mock_nvd.query_nvd.assert_not_called()
    assert len(findings_no_config) == 1
    assert len(findings_disabled) == 1
    assert all(f["source"] == "local_db" for f in findings_no_config)


def test_live_lookup_uses_cache_when_fresh(isolated_db):
    host = {
        "vendor": "Siemens", "model": "S7-1500", "firmware": "1.2.0",
        "evidence": [], "ot_ports": [],
    }
    cached_results = [{
        "id": "CVE-LIVE-1", "title": "Live cached finding", "severity": "High",
        "cvss_score": 7.5, "advisory": "https://example.com/live1", "cpe_criteria": [],
    }]

    with patch.object(cve_module.cve_cache, "get_cached", return_value=cached_results) as mock_get, \
         patch.object(cve_module, "nvd_client") as mock_nvd:
        findings = cve_module.correlate(host, cve_config={"live_lookup": True})

    mock_get.assert_called_once()
    mock_nvd.query_nvd.assert_not_called()  # cache hit - must not hit the network

    live_findings = [f for f in findings if f["source"] == "nvd_live"]
    assert len(live_findings) == 1
    assert live_findings[0]["cve"] == "CVE-LIVE-1"
    assert live_findings[0]["severity"] == "High"


def test_live_lookup_queries_nvd_on_cache_miss_and_caches_result(isolated_db):
    host = {
        "vendor": "Siemens", "model": "S7-1500", "firmware": "1.2.0",
        "evidence": [], "ot_ports": [],
    }
    live_results = [{
        "id": "CVE-LIVE-2", "title": "Fresh live finding", "severity": "Medium",
        "cvss_score": 5.0, "advisory": None, "cpe_criteria": [],
    }]

    with patch.object(cve_module.cve_cache, "get_cached", return_value=None), \
         patch.object(cve_module.cve_cache, "set_cached") as mock_set, \
         patch.object(cve_module.nvd_client, "query_nvd", return_value=live_results) as mock_query:
        findings = cve_module.correlate(
            host, cve_config={"live_lookup": True, "api_key": "k", "request_timeout": 5}
        )

    mock_query.assert_called_once_with("Siemens", "S7-1500", api_key="k", timeout=5)
    mock_set.assert_called_once_with("Siemens", "S7-1500", live_results)

    live_findings = [f for f in findings if f["source"] == "nvd_live"]
    assert len(live_findings) == 1
    assert live_findings[0]["cve"] == "CVE-LIVE-2"


def test_live_lookup_uses_default_30s_timeout_when_not_specified():
    host = {
        "vendor": "Siemens", "model": "S7-1500", "firmware": "1.2.0",
        "evidence": [], "ot_ports": [],
    }
    with patch.object(cve_module.cve_cache, "get_cached", return_value=None), \
         patch.object(cve_module.cve_cache, "set_cached"), \
         patch.object(cve_module.nvd_client, "query_nvd", return_value=[]) as mock_query:
        cve_module.correlate(host, cve_config={"live_lookup": True})

    mock_query.assert_called_once_with("Siemens", "S7-1500", api_key=None, timeout=30)



def test_live_lookup_dedupes_against_local_db_cve_ids(isolated_db):
    """A live NVD result for the same CVE already covered by a curated
    local_db entry must not be duplicated in the output."""

    host = {
        "vendor": "Siemens", "model": "S7-1500", "firmware": "1.2.0",
        "evidence": [], "ot_ports": [],
    }
    # TEST-CVE-1 is the curated local entry's id (see isolated_db fixture).
    live_results = [{
        "id": "TEST-CVE-1", "title": "Same issue via NVD", "severity": "High",
        "cvss_score": 7.0, "advisory": None, "cpe_criteria": [],
    }]

    with patch.object(cve_module.cve_cache, "get_cached", return_value=live_results):
        findings = cve_module.correlate(host, cve_config={"live_lookup": True})

    cve_ids = [f["cve"] for f in findings]
    assert cve_ids.count("TEST-CVE-1") == 1  # not duplicated
    assert not any(f["source"] == "nvd_live" for f in findings)


def test_live_lookup_failure_falls_back_to_local_only_silently(isolated_db):
    host = {
        "vendor": "Siemens", "model": "S7-1500", "firmware": "1.2.0",
        "evidence": [], "ot_ports": [],
    }

    with patch.object(cve_module.cve_cache, "get_cached", return_value=None), \
         patch.object(cve_module.nvd_client, "query_nvd", side_effect=ConnectionError("offline")):
        # Must not raise - this is the "no internet" / "NVD unreachable" path.
        findings = cve_module.correlate(host, cve_config={"live_lookup": True})

    assert len(findings) == 1
    assert findings[0]["source"] == "local_db"


def test_live_lookup_skipped_when_vendor_or_model_missing(isolated_db):
    host = {"vendor": None, "model": None, "firmware": None, "evidence": [], "ot_ports": []}

    with patch.object(cve_module, "nvd_client") as mock_nvd:
        findings = cve_module.correlate(host, cve_config={"live_lookup": True})

    mock_nvd.query_nvd.assert_not_called()
    assert findings == []


# --- detection tiers and per-host CVE-stage status (feeds the coverage report) ---

def _db_host(**kw):
    base = {"vendor": "Siemens", "model": "S7-1500", "firmware": "1.2.0", "evidence": [], "ot_ports": []}
    base.update(kw)
    return base


def test_firmware_confirmed_finding_is_version_matched(isolated_db):
    findings = cve_module.correlate(_db_host())
    assert findings[0]["detection"] == "version_matched"


def test_unreadable_firmware_finding_is_inconclusive(isolated_db):
    findings = cve_module.correlate(_db_host(firmware=None))
    assert findings and findings[0]["detection"] == "inconclusive"
    assert findings[0]["severity"] == "Info"


def test_rule_without_firmware_gate_is_product_matched(isolated_db, tmp_path):
    db = {"siemens": [{"id": "T-2", "title": "all versions", "match": {"model_contains": ["S7-1500"]},
                       "severity": "High", "advisory": "https://x"}]}
    path = tmp_path / "db.yaml"
    path.write_text(yaml.safe_dump(db))
    with patch.object(cve_module, "CVE_DB_YAML", path):
        findings = cve_module.correlate(_db_host())
    assert findings[0]["detection"] == "product_matched"


def test_live_findings_are_external_unverified(isolated_db):
    live = [{"id": "CVE-LIVE-9", "title": "t", "severity": "High", "cvss_score": 7.0,
             "advisory": None, "cpe_criteria": []}]
    with patch.object(cve_module.cve_cache, "get_cached", return_value=live):
        findings = cve_module.correlate(_db_host(), cve_config={"live_lookup": True})
    assert [f["detection"] for f in findings if f["source"] == "nvd_live"] == ["external_unverified"]


def test_local_status_records_rules_evaluated_and_matched(isolated_db):
    host = _db_host()
    cve_module.correlate(host)
    st = host["cve_status"]["local"]
    assert st["state"] == "evaluated" and st["rules"] >= 1 and st["matched"] == 1


def test_local_status_skipped_when_vendor_unknown(isolated_db):
    host = _db_host(vendor=None)
    cve_module.correlate(host)
    assert host["cve_status"]["local"] == {"state": "skipped", "reason": "vendor not identified"}


def test_local_status_skipped_when_vendor_has_no_rules(isolated_db):
    host = _db_host(vendor="Acme Corp")
    cve_module.correlate(host)
    assert host["cve_status"]["local"]["state"] == "skipped"
    assert "no local CVE rules" in host["cve_status"]["local"]["reason"]


def test_live_status_variants(isolated_db):
    host = _db_host()
    cve_module.correlate(host)
    assert host["cve_status"]["live"] == {"state": "disabled"}

    host = _db_host()
    with patch.object(cve_module.cve_cache, "get_cached", return_value=[]):
        cve_module.correlate(host, cve_config={"live_lookup": True})
    assert host["cve_status"]["live"]["state"] == "cache_hit"

    host = _db_host()
    with patch.object(cve_module.cve_cache, "get_cached", return_value=None), \
         patch.object(cve_module.nvd_client, "query_nvd", return_value=[]), \
         patch.object(cve_module.cve_cache, "set_cached"):
        cve_module.correlate(host, cve_config={"live_lookup": True})
    assert host["cve_status"]["live"]["state"] == "queried"

    host = _db_host()
    with patch.object(cve_module.cve_cache, "get_cached", return_value=None), \
         patch.object(cve_module.nvd_client, "query_nvd", side_effect=ConnectionError("no route")):
        cve_module.correlate(host, cve_config={"live_lookup": True})
    assert host["cve_status"]["live"]["state"] == "failed"
    assert "no route" in host["cve_status"]["live"]["reason"]

    host = _db_host(model=None)
    cve_module.correlate(host, cve_config={"live_lookup": True})
    assert host["cve_status"]["live"]["state"] == "skipped"


def test_siemens_mlfb_order_code_matches_model_family(isolated_db):
    host = {"vendor": "Siemens", "model": "6ES7 511-1AK01-0AB0", "firmware": "1.2.0", "evidence": []}
    findings = cve_module.correlate(host)
    assert len(findings) == 1
    assert findings[0]["cve"] == "TEST-CVE-1"
