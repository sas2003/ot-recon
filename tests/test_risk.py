from ot_recon.core.risk import assess_risk, _highest_severity, SEVERITY_ORDER
import pytest


def _host(ports, evidence=None):
    return {
        "ip": "10.0.0.1",
        "ot_ports": ports,
        "evidence": evidence or [],
        "vendor": None,
        "model": None,
        "firmware": None,
    }


def test_modbus_exposed_is_high_severity():
    host = _host([{"port": 502, "state": "open", "protocol": "Modbus"}])
    result = assess_risk([host])[0]

    findings = [f["finding"] for f in result["risks"]]
    assert any("Modbus exposed" in f for f in findings)
    modbus_finding = next(f for f in result["risks"] if "Modbus exposed" in f["finding"])
    assert modbus_finding["severity"] == "High"


def test_filtered_ports_do_not_trigger_open_risk():
    """A 'filtered' Modbus port should not be flagged as 'exposed' the same
    way an 'open' one is."""

    host = _host([{"port": 502, "state": "filtered", "protocol": "Modbus"}])
    result = assess_risk([host])[0]

    findings = [f["finding"] for f in result["risks"]]
    assert not any("Modbus exposed" in f for f in findings)


def test_br_safedesigner_is_critical():
    host = _host([{"port": 50000, "state": "open", "protocol": "B&R SafeDESIGNER"}])
    result = assess_risk([host])[0]

    finding = next(f for f in result["risks"] if "SafeDESIGNER" in f["finding"])
    assert finding["severity"] == "Critical"


def test_br_multiple_safedesigner_ports_dont_collapse():
    """Regression: risk.py used to key open-state by protocol *name*, so
    two ports sharing a protocol label (e.g. two SafeDESIGNER ports) could
    have an 'open' state masked by a later 'filtered' entry for the same
    name. Now tracked per-port."""

    host = _host([
        {"port": 50000, "state": "open", "protocol": "B&R SafeDESIGNER"},
        {"port": 51000, "state": "filtered", "protocol": "B&R SafeDESIGNER"},
    ])
    result = assess_risk([host])[0]

    finding = next(f for f in result["risks"] if "SafeDESIGNER" in f["finding"])
    assert finding["severity"] == "Critical"


def test_br_sdm_evidence_triggers_finding():
    host = _host(
        ports=[{"port": 80, "state": "open", "protocol": "HTTP"}],
        evidence=["System Diagnostics Manager (SDM) confirmed on port 80"],
    )
    result = assess_risk([host])[0]

    assert any("SDM diagnostics interface exposed" in f["finding"] for f in result["risks"])


def test_multiple_services_contextual_risk():
    host = _host([
        {"port": 21, "state": "open", "protocol": "FTP"},
        {"port": 22, "state": "open", "protocol": "SSH"},
        {"port": 80, "state": "open", "protocol": "HTTP"},
    ])
    result = assess_risk([host])[0]

    assert any("Multiple services exposed" in f["finding"] for f in result["risks"])


def test_risk_severity_rollup_picks_highest():
    host = _host([
        {"port": 22, "state": "open", "protocol": "SSH"},       # Low
        {"port": 502, "state": "open", "protocol": "Modbus"},   # High
    ])
    result = assess_risk([host])[0]

    assert result["risk_severity"] == "High"


def test_no_findings_gives_none_severity():
    host = _host([])
    result = assess_risk([host])[0]

    assert result["risks"] == []
    assert result["risk_severity"] == "None"


def test_highest_severity_helper_respects_order():
    findings = [
        {"severity": "Low"},
        {"severity": "Critical"},
        {"severity": "Medium"},
    ]
    assert _highest_severity(findings) == "Critical"
    assert _highest_severity([]) is None


def test_severity_order_is_well_formed():
    assert SEVERITY_ORDER[0] == "Critical"
    assert SEVERITY_ORDER[-1] == "Info"
    assert len(set(SEVERITY_ORDER)) == len(SEVERITY_ORDER)


@pytest.mark.parametrize("protocol,expected_substring,expected_severity", [
    ("EtherNet/IP", "EtherNet/IP exposed", "High"),
    ("EtherNet/IP-IO", "implicit I/O exposed", "Medium"),
    ("DNP3", "DNP3 exposed", "High"),
    ("OPC UA", "OPC UA exposed", "Medium"),
    ("VNC", "VNC open", "High"),
    ("SNMP", "SNMP open", "Medium"),
    ("S7", "Siemens S7 exposed", "High"),
    ("B&R mapp View", "mapp View HMI exposed", "Medium"),
])
def test_protocol_risk_flags(protocol, expected_substring, expected_severity):
    host = _host([{"port": 1, "state": "open", "protocol": protocol}])
    result = assess_risk([host])[0]

    match = next(
        (f for f in result["risks"] if expected_substring in f["finding"]), None
    )
    assert match is not None, f"expected a finding containing {expected_substring!r}"
    assert match["severity"] == expected_severity


def test_br_engineering_port_risk():
    host = _host([{"port": 11169, "state": "open", "protocol": "B&R ANSL"}])
    result = assess_risk([host])[0]

    assert any(
        "Automation Studio/PVI engineering port exposed" in f["finding"]
        for f in result["risks"]
    )


def test_finding_schema_has_all_phase1_fields():
    host = _host([
        {"port": 502, "state": "open", "protocol": "Modbus"},
        {"port": 50000, "state": "open", "protocol": "B&R SafeDESIGNER"},
        {"port": 80, "state": "open", "protocol": "HTTP"},
    ])
    result = assess_risk([host])[0]

    for finding in result["risks"]:
        assert "impact" in finding
        assert "likelihood" in finding
        assert "recommendation" in finding and len(finding["recommendation"]) > 10
        assert "remediation_priority" in finding
        assert finding["remediation_priority"] in ("P1", "P2", "P3", "P4", "P5")
        assert "related_ports" in finding
        assert isinstance(finding["related_ports"], list)


def test_calculate_risk_score_and_asset_multiplier():
    from ot_recon.core.risk import _calculate_risk_score

    # Critical (40) + High (20) = 60
    findings = [{"severity": "Critical"}, {"severity": "High"}]

    generic_score = _calculate_risk_score(findings, host_type="Unknown")
    assert generic_score == 60

    # Safety PLC: 60 * 1.3 = 78
    safety_score = _calculate_risk_score(findings, host_type="Safety PLC")
    assert safety_score == 78

    # PLC: 60 * 1.2 = 72
    plc_score = _calculate_risk_score(findings, host_type="PLC")
    assert plc_score == 72

    # Score should cap at 100
    huge_findings = [{"severity": "Critical"}] * 5  # 5 * 40 = 200
    capped_score = _calculate_risk_score(huge_findings, host_type="PLC")
    assert capped_score == 100


def test_host_summary_content():
    host = _host([
        {"port": 502, "state": "open", "protocol": "Modbus"},
    ])
    host["type"] = "PLC"
    host["vendor"] = "Schneider"

    result = assess_risk([host])[0]
    summary = result.get("summary")

    assert summary is not None
    assert "Schneider PLC" in summary
    assert "High severity" in summary
    assert "Modbus" in summary
    assert "Recommended action:" in summary
