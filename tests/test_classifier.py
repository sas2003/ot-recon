from ot_recon.core.classifier import classify


def _host(evidence=None, protocols=None, vendor=None):
    return {
        "ip": "10.0.0.1",
        "evidence": evidence or [],
        "vendor": vendor,
        "ot_ports": [{"protocol": p} for p in (protocols or [])],
    }


def test_siemens_hmi_evidence():
    data = [_host(evidence=["SIMATIC HMI"])]
    result = classify(data)
    assert result[0]["type"] == "HMI"
    assert result[0]["confidence"] == "Very High"


def test_siemens_plc_module_type_evidence():
    data = [_host(evidence=["S7comm response confirmed (PLC/CPU)"])]
    result = classify(data)
    assert result[0]["type"] == "PLC"
    assert result[0]["confidence"] == "Very High"


def test_rockwell_plc_device_type_evidence():
    data = [_host(evidence=["Device Type: Programmable Logic Controller"])]
    result = classify(data)
    assert result[0]["type"] == "PLC"
    assert result[0]["confidence"] == "Very High"


def test_br_safedesigner_takes_priority_as_safety_plc():
    data = [_host(evidence=["B&R SafeDESIGNER port open (50000)"])]
    result = classify(data)
    assert result[0]["type"] == "Safety PLC"
    assert result[0]["confidence"] == "High"


def test_br_mapp_view_classified_as_hmi():
    data = [_host(evidence=["mapp View confirmed on port 81"])]
    result = classify(data)
    assert result[0]["type"] == "HMI"
    assert result[0]["confidence"] == "High"


def test_br_sdm_classified_as_plc_cpu():
    data = [_host(evidence=["System Diagnostics Manager (SDM) confirmed on port 80"])]
    result = classify(data)
    assert result[0]["type"] == "PLC"
    assert result[0]["confidence"] == "High"
    assert result[0]["confidence_score"] == 80
    assert result[0]["detection_method"] == "active_probe"
    assert result[0]["evidence_based"] is True


def test_br_port_signature_only_is_lower_confidence():
    """When B&R evidence is only a bare port-signature (no HTTP
    confirmation), classification standardizes to PLC but with Medium
    confidence and port_signature detection method."""

    data = [_host(
        evidence=["B&R PVI legacy port open (11159)"],
        vendor="B&R Automation (unconfirmed - port signature only)",
    )]
    result = classify(data)
    assert result[0]["type"] == "PLC"
    assert result[0]["confidence"] == "Medium"
    assert result[0]["confidence_score"] == 50
    assert result[0]["detection_method"] == "port_signature"
    assert result[0]["evidence_based"] is True


def test_modbus_fallback_when_no_evidence():
    data = [_host(protocols=["Modbus"])]
    result = classify(data)
    assert result[0]["type"] == "Field Device"
    assert result[0]["confidence"] == "Medium"
    assert result[0]["confidence_score"] == 50
    assert result[0]["detection_method"] == "heuristic"
    assert result[0]["evidence_based"] is False


def test_opc_ua_fallback_classifies_as_industrial_server():
    """Regression: depends on enricher normalizing to 'OPC UA' (space),
    not 'OPC-UA' (hyphen) - see test_enricher.py."""

    data = [_host(protocols=["OPC UA"])]
    result = classify(data)
    assert result[0]["type"] == "Industrial Server"
    assert result[0]["confidence"] == "Medium"
    assert result[0]["confidence_score"] == 50
    assert result[0]["detection_method"] == "heuristic"


def test_unknown_when_nothing_matches():
    data = [_host()]
    result = classify(data)
    assert result[0]["type"] == "Unknown"
    assert result[0]["confidence"] == "Low"
    assert result[0]["confidence_score"] == 20
    assert result[0]["detection_method"] == "none"
    assert result[0]["evidence_based"] is False


def test_evidence_based_rules_take_priority_over_protocol_fallback():
    """A host with both strong evidence and a generic protocol match
    should be classified from the evidence, not the weaker fallback."""

    data = [_host(evidence=["S7comm response confirmed (PLC/CPU)"], protocols=["Modbus"])]
    result = classify(data)
    assert result[0]["type"] == "PLC"
    assert result[0]["confidence"] == "Very High"
    assert result[0]["confidence_score"] == 95
    assert result[0]["detection_method"] == "active_probe"
    assert result[0]["evidence_based"] is True


def test_generic_hmi_evidence_phrase():
    data = [_host(evidence=["Human-Machine Interface detected"])]
    result = classify(data)
    assert result[0]["type"] == "HMI"
    assert result[0]["confidence"] == "Very High"
    assert result[0]["confidence_score"] == 95


def test_s7_protocol_fallback_when_no_evidence():
    data = [_host(protocols=["S7"])]
    result = classify(data)
    assert result[0]["type"] == "PLC"
    assert result[0]["confidence"] == "Medium"
    assert result[0]["confidence_score"] == 50
    assert result[0]["detection_method"] == "heuristic"
    assert result[0]["evidence_based"] is False


def test_ethernetip_protocol_fallback_when_no_evidence():
    data = [_host(protocols=["EtherNet/IP"])]
    result = classify(data)
    assert result[0]["type"] == "PLC"
    assert result[0]["confidence"] == "Medium"
    assert result[0]["confidence_score"] == 50
    assert result[0]["detection_method"] == "heuristic"
    assert result[0]["evidence_based"] is False


def test_controlled_vocabulary_enforcement():
    from ot_recon.core.classifier import CONTROLLED_TYPES

    test_hosts = [
        _host(evidence=["SIMATIC HMI"]),
        _host(evidence=["S7comm response confirmed (PLC/CPU)"]),
        _host(evidence=["SafeDESIGNER"]),
        _host(protocols=["Modbus"]),
        _host(protocols=["OPC UA"]),
        _host(),
    ]
    results = classify(test_hosts)
    for h in results:
        assert h["type"] in CONTROLLED_TYPES
        assert h["confidence"] in ("Very High", "High", "Medium", "Low")
        assert 0 <= h["confidence_score"] <= 100
        assert h["detection_method"] in ("active_probe", "port_signature", "heuristic", "none")
        assert isinstance(h["evidence_based"], bool)


def test_classify_uses_unified_services_fallback():
    # ot_ports empty or missing, but services has Modbus
    host = {
        "ip": "10.0.0.99",
        "ot_ports": [],
        "services": [{"port": 502, "protocol": "Modbus"}],
    }
    result = classify([host])[0]
    assert result["type"] == "Field Device"
    assert result["confidence"] == "Medium"


def test_filtered_protocols_do_not_trigger_fallback_classification():
    """Filtered ports must not be treated as running the protocol for classification."""
    host = {
        "ip": "10.0.0.100",
        "ot_ports": [
            {"port": 502, "protocol": "Modbus", "state": "filtered"},
            {"port": 102, "protocol": "S7", "state": "filtered"},
        ],
        "evidence": [],
    }
    result = classify([host])[0]
    assert result["type"] == "Unknown"
    assert result["confidence"] == "Low"
    assert result["confidence_score"] == 20
    assert result["detection_method"] == "none"
    assert result["evidence_based"] is False
