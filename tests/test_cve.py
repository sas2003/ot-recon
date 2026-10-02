import yaml
import pytest

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
