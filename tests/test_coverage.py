from ot_recon.core import coverage


def _svc(port, proto, category="ot", state="open"):
    return {"port": port, "protocol": proto, "category": category, "state": state}


def _host(**kw):
    base = {"ip": "10.0.0.1", "services": [], "ot_ports": [], "probes": [], "risks": [],
            "vendor": None, "model": None, "firmware": None, "type": "Unknown",
            "evidence_based": False, "cve_status": {}}
    base.update(kw)
    return base


def _probe(name, status, error=None):
    return {"probe": name, "status": status, "error": error}


def _ctx(**kw):
    base = {"udp_scanned": True, "cve_live": True, "profile": {"name": "standard"}, "excluded": []}
    base.update(kw)
    return base


def _gaps(host, ctx=None):
    return coverage.build_host_coverage(host, ctx or _ctx())["gaps"]


# --- host status ---

def test_host_with_no_ot_services_is_not_applicable():
    cov = coverage.build_host_coverage(_host(services=[_svc(22, "SSH", "it")]), _ctx())
    assert cov["status"] == "n/a" and cov["gaps"] == []


def test_fully_assessed_host_has_no_gaps():
    host = _host(
        services=[_svc(102, "S7")], vendor="Siemens", model="S7-1500", firmware="2.9.3",
        type="PLC", evidence_based=True, probes=[_probe("s7-info", "data")],
        cve_status={"local": {"state": "evaluated", "rules": 4, "matched": 0},
                    "live": {"state": "queried", "results": 0}},
    )
    cov = coverage.build_host_coverage(host, _ctx())
    assert cov["status"] == "full" and cov["gaps"] == []


def test_ot_host_nothing_learned_is_limited():
    host = _host(services=[_svc(102, "S7")], probes=[_probe("s7-info", "no_data")])
    cov = coverage.build_host_coverage(host, _ctx())
    assert cov["status"] == "limited"
    assert any("could not be fingerprinted" in g for g in cov["gaps"])


# --- the specific gaps ---

def test_unreadable_firmware_counts_inconclusive_checks():
    host = _host(
        services=[_svc(80, "HTTP", "it"), _svc(11169, "B&R ANSL")], vendor="B&R Automation",
        probes=[_probe("br-info", "data")],
        risks=[{"detection": "inconclusive"}, {"detection": "inconclusive"}, {"detection": "observed"}],
    )
    gaps = _gaps(host)
    assert any("Firmware version could not be read - 2 vulnerability check(s)" in g for g in gaps)


def test_firmware_unknown_without_inconclusive_checks_is_not_a_gap():
    host = _host(services=[_svc(102, "S7")], vendor="Siemens", probes=[_probe("s7-info", "data")],
                 evidence_based=True, type="PLC")
    assert not any("Firmware" in g for g in _gaps(host))


def test_timed_out_probe_is_reported_with_its_reason():
    host = _host(services=[_svc(44818, "EtherNet/IP")],
                 probes=[_probe("enip-info", "timeout", "no result within 30s")])
    gaps = _gaps(host)
    assert any("enip-info" in g and "timed out" in g for g in gaps)


def test_vendor_inferred_from_port_signature_is_flagged():
    host = _host(services=[_svc(11169, "B&R ANSL")],
                 vendor="B&R Automation (unconfirmed - port signature only)")
    assert any("inferred from port numbers only" in g for g in _gaps(host))


def test_protocols_without_a_probe_are_called_out():
    for proto, port in (("Modbus", 502), ("DNP3", 20000), ("OPC UA", 4840)):
        gaps = _gaps(_host(services=[_svc(port, proto)]))
        assert any(proto in g and "no read-only identification probe" in g for g in gaps), proto


def test_br_engineering_ports_flagged_as_unprobed():
    gaps = _gaps(_host(services=[_svc(50000, "B&R SafeDESIGNER"), _svc(11169, "B&R ANSL")]))
    assert any("11169, 50000" in g and "no public specification" in g for g in gaps)


def test_heuristic_classification_is_flagged():
    host = _host(services=[_svc(502, "Modbus")], type="Field Device", evidence_based=False)
    assert any("inferred from protocol heuristics" in g for g in _gaps(host))


def test_evidence_based_classification_is_not_flagged():
    host = _host(services=[_svc(102, "S7")], type="PLC", evidence_based=True,
                 vendor="Siemens", probes=[_probe("s7-info", "data")])
    assert not any("heuristics" in g for g in _gaps(host))


def test_failed_live_lookup_is_a_gap():
    host = _host(services=[_svc(102, "S7")], vendor="Siemens", model="S7-1500", type="PLC",
                 evidence_based=True, probes=[_probe("s7-info", "data")],
                 cve_status={"live": {"state": "failed", "reason": "timed out"}})
    assert any("Live NVD lookup failed (timed out)" in g for g in _gaps(host))


def test_disabled_live_lookup_is_not_a_per_host_gap():
    host = _host(services=[_svc(102, "S7")], vendor="Siemens", type="PLC", evidence_based=True,
                 probes=[_probe("s7-info", "data")], cve_status={"live": {"state": "disabled"}})
    assert not any("NVD" in g for g in _gaps(host))   # it's reported once, scan-wide


def test_cve_correlation_skipped_on_ot_host_is_a_gap_but_not_on_it_host():
    ot = _host(services=[_svc(502, "Modbus")],
               cve_status={"local": {"state": "skipped", "reason": "vendor not identified"}})
    it = _host(services=[_svc(22, "SSH", "it")],
               cve_status={"local": {"state": "skipped", "reason": "vendor not identified"}})
    assert any("CVE correlation did not run" in g for g in _gaps(ot))
    assert _gaps(it) == []


# --- scan-level ---

def test_scan_gaps_udp_and_live_lookup():
    cov = coverage.build_scan_coverage([], _ctx(udp_scanned=False, cve_live=False))
    text = " ".join(cov["gaps"])
    assert "UDP was not scanned" in text and "--udp" in text
    assert "Live NVD lookup was off" in text and "--cve-live" in text


def test_scan_gaps_absent_when_those_features_were_on():
    cov = coverage.build_scan_coverage([], _ctx())
    assert cov["gaps"] == []


def test_scan_gaps_count_hosts_per_unprobed_protocol():
    data = [_host(services=[_svc(502, "Modbus")]), _host(services=[_svc(502, "Modbus")]),
            _host(services=[_svc(4840, "OPC UA")])]
    gaps = coverage.build_scan_coverage(data, _ctx())["gaps"]
    assert any("Modbus found on 2 host(s)" in g for g in gaps)
    assert any("OPC UA found on 1 host(s)" in g for g in gaps)


def test_scan_gap_counts_failed_probes():
    data = [_host(probes=[_probe("a", "timeout"), _probe("b", "error"), _probe("c", "data")])]
    assert any("2 fingerprint probe(s)" in g for g in coverage.build_scan_coverage(data, _ctx())["gaps"])


def test_notes_state_methodology_and_exclusions():
    cov = coverage.build_scan_coverage([], _ctx(profile={"name": "safe"}, excluded=["10.0.0.5"]))
    text = " ".join(cov["notes"])
    assert "'safe' profile" in text
    assert "no exploits, no authentication attempts" in text
    assert "10.0.0.5" in text


def test_annotate_attaches_coverage_and_counts():
    data = [_host(services=[_svc(22, "SSH", "it")]),
            _host(services=[_svc(102, "S7")], probes=[_probe("s7-info", "no_data")])]
    ctx = _ctx()
    out = coverage.annotate(data, ctx)

    assert out is data
    assert data[0]["coverage"]["status"] == "n/a" and data[1]["coverage"]["status"] == "limited"
    assert ctx["coverage"]["host_status_counts"] == {"full": 0, "partial": 0, "limited": 1, "n/a": 1}
