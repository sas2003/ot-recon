"""Integration test: runs the real pipeline (enrich -> fingerprint ->
classify -> risk) end to end for one host per vendor, with only the
external nmap/HTTP calls mocked. Locks in that the modules still compose
correctly as each one changes independently.
"""

from unittest.mock import patch

from ot_recon.core.enricher import enrich
from ot_recon.core.fingerprinter import fingerprint
from ot_recon.core.classifier import classify
from ot_recon.core.risk import assess_risk


def _run_result(stdout=""):
    return type("R", (), {"stdout": stdout, "returncode": 0})()


def test_full_pipeline_siemens_rockwell_br():
    raw = [
        {  # Siemens S7-1500, vulnerable firmware
            "ip": "10.0.0.11",
            "ports": [
                {"port": 102, "state": "open", "service": "iso-tsap"},
                {"port": 80, "state": "open", "service": "http"},
            ],
        },
        {  # Rockwell CompactLogix 5370 (always-vulnerable model family)
            "ip": "10.0.0.13",
            "ports": [{"port": 44818, "state": "open", "service": "unknown"}],
        },
        {  # B&R with SDM confirmed + SafeDESIGNER exposed
            "ip": "10.0.0.12",
            "ports": [
                {"port": 80, "state": "open", "service": "unknown"},
                {"port": 50000, "state": "open", "service": "unknown"},
            ],
        },
        {  # Plain host, nothing OT-related
            "ip": "10.0.0.14",
            "ports": [{"port": 22, "state": "open", "service": "ssh"}],
        },
    ]

    data = enrich(raw)

    def fake_nmap(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "s7-info" in cmd_str:
            return _run_result(
                "Siemens S7 device\nModule: SIMATIC S7-1500\nVersion: V1.2.0\n"
                "Module Type: CPU 1515-2 PN\nSystem Name: Line1_PLC\n"
            )
        if "enip-info" in cmd_str:
            return _run_result(
                "vendor: Rockwell Automation/Allen-Bradley\n"
                "productName: CompactLogix 5370\nrevision: 33.011\n"
                "type: Programmable Logic Controller\n"
            )
        if "br-info.nse" in cmd_str:
            if "10.0.0.12" in cmd_str:
                return _run_result(
                    "| br-info:\n"
                    "|   Vendor: B&R Automation\n"
                    "|   Component: System Diagnostics Manager (SDM) on port 80\n"
                    "|_  Title (/sdm): System Diagnostics Manager\n"
                )
        return _run_result("")

    with patch("subprocess.run", side_effect=fake_nmap):
        data = fingerprint(data, verbose=False, workers=4)

    data = classify(data)
    data = assess_risk(data)

    by_ip = {h["ip"]: h for h in data}

    # Siemens
    siemens = by_ip["10.0.0.11"]
    assert siemens["vendor"] == "Siemens"
    assert siemens["type"] == "PLC"
    assert siemens["risk_severity"] in ("Critical", "High")
    assert any(r["cve"] for r in siemens["risks"] if r.get("cve"))

    # Rockwell
    rockwell = by_ip["10.0.0.13"]
    assert rockwell["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert rockwell["type"] == "PLC"
    assert any("CVE-2019-10954" in (r.get("cve") or "") for r in rockwell["risks"])

    # B&R
    br = by_ip["10.0.0.12"]
    assert br["vendor"] == "B&R Automation"
    assert br["type"] == "Safety PLC"  # SafeDESIGNER takes priority over SDM
    assert br["risk_severity"] == "Critical"  # SafeDESIGNER exposure

    # Plain host
    plain = by_ip["10.0.0.14"]
    assert plain["type"] == "Unknown"
    assert plain["risk_severity"] == "Low"


def test_pipeline_localhost_filtered_ports_not_misclassified():
    """End-to-end regression test replicating the localhost scan:
    Host has open HTTP, HTTPS, FTP, but all OT ports (S7, Modbus, B&R, ENIP)
    are 'filtered' (firewalled/no-response).
    Must NOT be classified as B&R Safety PLC or have fake OT findings."""
    raw = [
        {
            "ip": "127.0.0.1",
            "ports": [
                {"port": 21, "state": "open", "service": "ftp"},
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"},
                {"port": 81, "state": "filtered", "service": "hosts2-ns"},
                {"port": 102, "state": "filtered", "service": "iso-tsap"},
                {"port": 161, "state": "filtered", "service": "snmp"},
                {"port": 502, "state": "filtered", "service": "mbap"},
                {"port": 2222, "state": "filtered", "service": "EtherNetIP-1"},
                {"port": 4840, "state": "filtered", "service": "opcua-tcp"},
                {"port": 5900, "state": "filtered", "service": "vnc"},
                {"port": 8084, "state": "filtered", "service": "websnp"},
                {"port": 11159, "state": "filtered", "service": "unknown"},
                {"port": 11160, "state": "filtered", "service": "unknown"},
                {"port": 11169, "state": "filtered", "service": "unknown"},
                {"port": 20000, "state": "filtered", "service": "dnp"},
                {"port": 44818, "state": "filtered", "service": "EtherNetIP-2"},
                {"port": 50000, "state": "filtered", "service": "ibm-db2"},
                {"port": 51000, "state": "filtered", "service": "unknown"},
            ],
        }
    ]

    data = enrich(raw)

    with patch("subprocess.run", return_value=_run_result("")):
        data = fingerprint(data, verbose=False, workers=1)

    data = classify(data)
    data = assess_risk(data)

    host = data[0]

    # Verify device is not misidentified
    assert host["vendor"] is None
    assert host["type"] == "Unknown"
    assert host["confidence"] == "Low"
    assert host["detection_method"] == "none"
    assert host["evidence_based"] is False

    # Verify findings only relate to the truly OPEN services (FTP, HTTP)
    finding_texts = [r["finding"] for r in host["risks"]]
    assert any("FTP open" in f for f in finding_texts)
    assert any("HTTP open" in f for f in finding_texts)
    assert not any("SafeDESIGNER" in f for f in finding_texts)
    assert not any("Modbus" in f for f in finding_texts)
    assert not any("S7" in f for f in finding_texts)
    assert not any("EtherNet/IP" in f for f in finding_texts)
