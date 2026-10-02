from ot_recon.core.enricher import enrich


def test_port_based_detection_matches_int_keys():
    """Regression test: ports.yaml keys parse as int via YAML, and the
    enricher must compare using int, not str(port). This bug previously
    made port-based detection silently never fire for any port."""

    data = [{
        "ip": "10.0.0.1",
        "ports": [{"port": 502, "state": "open", "service": "unknown"}],
    }]

    result = enrich(data)

    assert len(result[0]["ot_ports"]) == 1
    assert result[0]["ot_ports"][0]["protocol"] == "Modbus"
    assert result[0]["ot_ports"][0]["confidence"] == "Medium"


def test_br_ports_are_recognized():
    """B&R-specific ports (no default nmap service name) must still be
    enriched via the port map."""

    data = [{
        "ip": "10.0.0.2",
        "ports": [
            {"port": 11169, "state": "open", "service": "unknown"},
            {"port": 50000, "state": "open", "service": "unknown"},
            {"port": 81, "state": "open", "service": "unknown"},
        ],
    }]

    result = enrich(data)
    protocols = {p["port"]: p["protocol"] for p in result[0]["ot_ports"]}

    assert protocols[11169] == "B&R ANSL"
    assert protocols[50000] == "B&R SafeDESIGNER"
    assert protocols[81] == "B&R mapp View"


def test_service_name_gives_higher_confidence_than_port_alone():
    """Method 2 (service-name match) should be treated as stronger evidence
    (High) than a bare port-number match (Medium)."""

    data = [{
        "ip": "10.0.0.3",
        "ports": [{"port": 502, "state": "open", "service": "mbap"}],
    }]

    result = enrich(data)

    assert result[0]["ot_ports"][0]["confidence"] == "High"


def test_opc_ua_naming_is_consistent():
    """Regression test: ports.yaml previously said 'OPC-UA' (hyphen) while
    classifier/risk checked for 'OPC UA' (space), silently breaking OPC UA
    detection end-to-end."""

    data = [{
        "ip": "10.0.0.4",
        "ports": [{"port": 4840, "state": "open", "service": "unknown"}],
    }]

    result = enrich(data)

    assert result[0]["ot_ports"][0]["protocol"] == "OPC UA"


def test_state_is_preserved_regardless_of_openness():
    """Enricher deliberately does not filter by state - it preserves
    open/filtered ports so they still surface in reports. Filtering by
    'open' happens downstream in risk.py, not here."""

    data = [{
        "ip": "10.0.0.5",
        "ports": [{"port": 502, "state": "filtered", "service": "mbap"}],
    }]

    result = enrich(data)

    assert len(result[0]["ot_ports"]) == 1
    assert result[0]["ot_ports"][0]["state"] == "filtered"
    assert result[0]["ot_ports"][0]["protocol"] == "Modbus"


def test_unmapped_port_and_service_is_ignored():
    data = [{
        "ip": "10.0.0.6",
        "ports": [{"port": 9999, "state": "open", "service": "unknown"}],
    }]

    result = enrich(data)

    assert result[0]["ot_ports"] == []


def test_unified_services_array_created_with_metadata():
    data = [{
        "ip": "10.0.0.7",
        "ports": [
            {"port": 502, "state": "open", "service": "mbap"},
            {"port": 22, "state": "open", "service": "ssh"},
            {"port": 9999, "state": "open", "service": "custom_app", "version": "1.0"},
        ],
    }]

    result = enrich(data)
    services = result[0]["services"]

    assert len(services) == 3
    s_by_port = {s["port"]: s for s in services}

    # Modbus
    assert s_by_port[502]["protocol"] == "Modbus"
    assert s_by_port[502]["category"] == "ot"
    assert s_by_port[502]["authentication"] == "none"

    # SSH
    assert s_by_port[22]["protocol"] == "SSH"
    assert s_by_port[22]["category"] == "it"
    assert s_by_port[22]["authentication"] == "encrypted"

    # Unmapped port still appears in unified services
    assert s_by_port[9999]["protocol"] is None
    assert s_by_port[9999]["category"] == "unknown"
    assert s_by_port[9999]["version"] == "1.0"


def test_authentication_profiles():
    data = [{
        "ip": "10.0.0.8",
        "ports": [
            {"port": 80, "state": "open", "service": "http"},
            {"port": 443, "state": "open", "service": "https"},
            {"port": 161, "state": "open", "service": "snmp"},
            {"port": 4840, "state": "open", "service": "opcua"},
        ],
    }]

    result = enrich(data)
    s_by_port = {s["port"]: s for s in result[0]["services"]}

    assert s_by_port[80]["authentication"] == "cleartext"
    assert s_by_port[443]["authentication"] == "encrypted"
    assert s_by_port[161]["authentication"] == "weak"
    assert s_by_port[4840]["authentication"] == "configurable"
