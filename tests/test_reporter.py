from ot_recon.core.reporter import generate_report, SEVERITY_STYLE


def _host(ip, type_="PLC", vendor="Siemens", risks=None, ot_ports=None, risk_severity="None"):
    return {
        "ip": ip,
        "type": type_,
        "vendor": vendor,
        "model": "Test Model",
        "firmware": "1.0",
        "confidence": "High",
        "ot_ports": ot_ports or [{"protocol": "S7"}],
        "risks": risks or [],
        "risk_severity": risk_severity,
    }


def test_generate_report_runs_without_crashing_on_empty_data(capsys):
    generate_report([])
    captured = capsys.readouterr()
    assert "OT Recon Report" in captured.out


def test_generate_report_shows_hosts_and_summary(capsys):
    data = [
        _host("10.0.0.1", risks=[
            {"finding": "Modbus exposed", "severity": "High", "cve": None, "advisory": None},
        ], risk_severity="High"),
        _host("10.0.0.2", type_="Unknown", vendor=None, ot_ports=[], risk_severity="None"),
    ]

    generate_report(data)
    captured = capsys.readouterr()

    assert "10.0.0.1" in captured.out
    assert "10.0.0.2" in captured.out
    assert "Hosts discovered : 2" in captured.out
    assert "OT Assets found  : 1" in captured.out  # only host 1 has a non-Unknown type


def test_generate_report_detailed_findings_include_cve_reference(capsys):
    data = [
        _host("10.0.0.1", risks=[
            {
                "finding": "Test vulnerable firmware",
                "severity": "Critical",
                "cve": "CVE-2025-40943",
                "advisory": "https://example.com/advisory",
            },
        ], risk_severity="Critical"),
    ]

    generate_report(data)
    captured = capsys.readouterr()

    assert "CVE-2025-40943" in captured.out
    assert "https://example.com/advisory" in captured.out


def test_generate_report_severity_counts_are_accurate(capsys):
    data = [
        _host("10.0.0.1", risks=[
            {"finding": "a", "severity": "Critical", "cve": None, "advisory": None},
            {"finding": "b", "severity": "High", "cve": None, "advisory": None},
        ], risk_severity="Critical"),
        _host("10.0.0.2", risks=[
            {"finding": "c", "severity": "Low", "cve": None, "advisory": None},
        ], risk_severity="Low"),
    ]

    generate_report(data)
    captured = capsys.readouterr()

    assert "Critical=1" in captured.out
    assert "High=1" in captured.out
    assert "Low=1" in captured.out
    assert "Medium=0" in captured.out


def test_severity_style_covers_all_levels():
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        assert level in SEVERITY_STYLE


def test_generate_diff_report_no_changes(capsys):
    from ot_recon.core.reporter import generate_diff_report

    diff = {"new_hosts": [], "removed_hosts": [], "host_changes": {}}
    generate_diff_report(diff, "old_ts", "new_ts")

    out = capsys.readouterr().out
    assert "No changes detected" in out
    assert "old_ts" in out and "new_ts" in out


def test_generate_diff_report_new_and_removed_hosts(capsys):
    from ot_recon.core.reporter import generate_diff_report

    diff = {"new_hosts": ["10.0.0.9"], "removed_hosts": ["10.0.0.8"], "host_changes": {}}
    generate_diff_report(diff)

    out = capsys.readouterr().out
    assert "10.0.0.9" in out
    assert "10.0.0.8" in out
    assert "New hosts" in out
    assert "no longer seen" in out


def test_generate_diff_report_full_host_change(capsys):
    from ot_recon.core.reporter import generate_diff_report

    diff = {
        "new_hosts": [],
        "removed_hosts": [],
        "host_changes": {
            "10.0.0.1": {
                "severity_change": ("Low", "Critical"),
                "vendor_change": (None, "Siemens"),
                "model_change": (None, "S7-1500"),
                "firmware_change": ("1.0.0", "2.0.0"),
                "new_ports": [(502, "tcp")],
                "closed_ports": [(80, "tcp")],
                "new_findings": [
                    {"finding": "Modbus exposed", "severity": "High", "cve": None},
                ],
                "resolved_findings": [
                    {"finding": "HTTP open", "severity": "Low", "cve": None},
                ],
            }
        },
    }

    generate_diff_report(diff)
    out = capsys.readouterr().out

    assert "10.0.0.1" in out
    assert "Low" in out and "Critical" in out
    assert "Siemens" in out
    assert "S7-1500" in out
    assert "1.0.0" in out and "2.0.0" in out
    assert "502/tcp" in out
    assert "80/tcp" in out
    assert "Modbus exposed" in out
    assert "resolved: HTTP open" in out


def test_generate_report_sorts_hosts_by_risk_score(capsys):
    data = [
        {"ip": "10.0.0.1", "type": "Field Device", "vendor": "Generic", "risk_score": 10, "risk_severity": "Low", "ot_ports": [], "risks": [{"finding": "Low finding", "severity": "Low"}]},
        {"ip": "10.0.0.2", "type": "PLC", "vendor": "Siemens", "risk_score": 85, "risk_severity": "High", "ot_ports": [], "risks": [{"finding": "High finding", "severity": "High"}]},
    ]
    generate_report(data)
    out = capsys.readouterr().out

    # In output, 10.0.0.2 (High risk) must appear before 10.0.0.1 (Low risk)
    idx_high = out.index("10.0.0.2")
    idx_low = out.index("10.0.0.1")
    assert idx_high < idx_low


def test_filtered_protocols_omitted_and_deduplicated_in_report(capsys):
    data = [{
        "ip": "10.0.0.1",
        "type": "Unknown",
        "vendor": None,
        "ot_ports": [
            {"protocol": "HTTP", "state": "open"},
            {"protocol": "HTTPS", "state": "open"},
            {"protocol": "B&R SafeDESIGNER", "state": "filtered"},
            {"protocol": "B&R SafeDESIGNER", "state": "filtered"},
            {"protocol": "S7", "state": "filtered"},
        ],
        "risks": [],
    }]
    generate_report(data)
    out = capsys.readouterr().out

    assert "HTTP, HTTPS" in out
    assert "SafeDESIGNER" not in out
    assert "S7" not in out
