import json
import csv

from ot_recon.core.exporter import export_json, export_csv


def _sample_data():
    return [
        {
            "ip": "10.0.0.11",
            "type": "PLC",
            "vendor": "Siemens",
            "model": "S7-1500",
            "firmware": "V1.2.0",
            "confidence": "Very High",
            "ot_ports": [{"protocol": "S7"}, {"protocol": "HTTP"}],
            "risk_severity": "Critical",
            "risks": [
                {"finding": "Siemens S7 exposed", "severity": "High", "cve": None, "advisory": None},
                {
                    "finding": "Test CVE finding",
                    "severity": "Critical",
                    "cve": "CVE-2025-40943",
                    "advisory": "https://example.com/advisory",
                },
            ],
        },
        {
            "ip": "10.0.0.14",
            "type": "Unknown",
            "vendor": None,
            "model": None,
            "firmware": None,
            "confidence": "Low",
            "ot_ports": [{"protocol": "SSH"}],
            "risk_severity": "Low",
            "risks": [],
        },
    ]


def test_export_json_round_trips(tmp_path):
    data = _sample_data()
    out_path = tmp_path / "report.json"

    export_json(data, out_path)

    with open(out_path) as f:
        payload = json.load(f)

    assert payload["host_count"] == 2
    assert "generated_at" in payload
    assert payload["hosts"][0]["ip"] == "10.0.0.11"
    assert payload["hosts"][0]["risks"][1]["cve"] == "CVE-2025-40943"


def test_export_csv_one_row_per_finding(tmp_path):
    data = _sample_data()
    out_path = tmp_path / "report.csv"

    export_csv(data, out_path)

    with open(out_path, newline="") as f:
        rows = list(csv.DictReader(f))

    # host 1 has 2 findings -> 2 rows; host 2 has 0 findings -> 1 blank row
    assert len(rows) == 3

    host1_rows = [r for r in rows if r["ip"] == "10.0.0.11"]
    assert len(host1_rows) == 2
    assert host1_rows[1]["cve"] == "CVE-2025-40943"
    assert host1_rows[1]["advisory"] == "https://example.com/advisory"

    host2_rows = [r for r in rows if r["ip"] == "10.0.0.14"]
    assert len(host2_rows) == 1
    assert host2_rows[0]["finding"] == ""
    assert host2_rows[0]["cve"] == ""


def test_export_csv_protocols_joined(tmp_path):
    data = _sample_data()
    out_path = tmp_path / "report.csv"

    export_csv(data, out_path)

    with open(out_path, newline="") as f:
        rows = list(csv.DictReader(f))

    assert rows[0]["protocols"] == "S7, HTTP"


def test_export_json_handles_empty_dataset(tmp_path):
    out_path = tmp_path / "empty.json"
    export_json([], out_path)

    with open(out_path) as f:
        payload = json.load(f)

    assert payload["host_count"] == 0
    assert payload["hosts"] == []


def test_export_csv_includes_phase1_columns(tmp_path):
    data = [
        {
            "ip": "10.0.0.1",
            "type": "PLC",
            "vendor": "Siemens",
            "model": "S7-1500",
            "firmware": "V1.0",
            "confidence": "High",
            "ot_ports": [{"protocol": "S7"}],
            "risk_severity": "High",
            "risk_score": 75,
            "summary": "Sample summary text",
            "risks": [
                {
                    "finding": "Siemens S7 exposed",
                    "severity": "High",
                    "remediation_priority": "P2",
                    "impact": "Critical",
                    "likelihood": "Medium",
                    "recommendation": "Isolate port 102",
                    "related_ports": [102],
                    "cve": None,
                    "advisory": None,
                }
            ],
        }
    ]
    out_path = tmp_path / "phase1_report.csv"
    export_csv(data, out_path)

    with open(out_path, newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 1
    r = rows[0]
    assert r["risk_score"] == "75"
    assert r["summary"] == "Sample summary text"
    assert r["remediation_priority"] == "P2"
    assert r["impact"] == "Critical"
    assert r["likelihood"] == "Medium"
    assert r["recommendation"] == "Isolate port 102"
    assert r["related_ports"] == "102"


def test_export_json_includes_network_summary_and_sorts_by_risk(tmp_path):
    data = [
        {
            "ip": "10.0.0.1",
            "type": "Field Device",
            "vendor": "Generic",
            "risk_score": 10,
            "risks": [{"severity": "Low"}],
        },
        {
            "ip": "10.0.0.2",
            "type": "Safety PLC",
            "vendor": "B&R Automation",
            "risk_score": 90,
            "risks": [{"severity": "Critical"}, {"severity": "High"}],
        },
        {
            "ip": "10.0.0.3",
            "type": "Unknown",
            "vendor": None,
            "risk_score": 0,
            "risks": [],
        },
    ]

    out_path = tmp_path / "network_summary_report.json"
    export_json(data, out_path)

    with open(out_path) as f:
        payload = json.load(f)

    # 1. Network Summary Block
    summary = payload["network_summary"]
    assert summary["total_hosts"] == 3
    assert summary["ot_assets"] == 2  # Field Device + Safety PLC
    assert summary["max_risk_score"] == 90
    assert summary["severity_counts"]["Critical"] == 1
    assert summary["severity_counts"]["High"] == 1
    assert summary["severity_counts"]["Low"] == 1
    assert summary["type_distribution"]["Safety PLC"] == 1
    assert summary["vendor_distribution"]["B&R Automation"] == 1

    # 2. Triage sorting: highest risk first
    assert payload["hosts"][0]["ip"] == "10.0.0.2"
    assert payload["hosts"][1]["ip"] == "10.0.0.1"
    assert payload["hosts"][2]["ip"] == "10.0.0.3"


def test_export_csv_includes_phase2_metadata_columns(tmp_path):
    data = [
        {
            "ip": "10.0.0.5",
            "type": "PLC",
            "confidence": "Very High",
            "confidence_score": 95,
            "detection_method": "active_probe",
            "evidence_based": True,
            "ot_ports": [],
            "risks": [],
        }
    ]
    out_path = tmp_path / "phase2_meta.csv"
    export_csv(data, out_path)

    with open(out_path, newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 1
    row = rows[0]
    assert row["confidence_score"] == "95"
    assert row["detection_method"] == "active_probe"
    assert row["evidence_based"] == "True"
