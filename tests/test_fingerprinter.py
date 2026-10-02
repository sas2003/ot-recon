import time
from unittest.mock import patch, MagicMock

from ot_recon.core import fingerprinter


def _run_result(stdout=""):
    return type("R", (), {"stdout": stdout, "returncode": 0})()


def _host(ports):
    return {
        "ip": "10.0.0.1",
        "ot_ports": [{"port": p, "protocol": proto} for p, proto in ports],
    }


def test_siemens_s7_extracts_vendor_model_firmware_evidence():
    host = _host([(102, "S7")])
    fake_output = (
        "Siemens S7 device\n"
        "Module: SIMATIC S7-1500\n"
        "Version: V2.9.3\n"
        "Module Type: CPU 1515-2 PN\n"
        "Basic Hardware: 6ES7 515-2AM01-0AB0\n"
        "Serial Number: S C-F0R1337\n"
        "System Name: Line1_PLC\n"
    )

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "Siemens"
    assert result["model"] == "SIMATIC S7-1500"
    assert result["firmware"] == "V2.9.3"
    assert any("S7 Module Type: CPU 1515-2 PN" in e for e in result["evidence"])
    assert any("Basic Hardware: 6ES7 515-2AM01-0AB0" in e for e in result["evidence"])
    assert any("Serial Number: S C-F0R1337" in e for e in result["evidence"])
    assert any("System Name: Line1_PLC" in e for e in result["evidence"])
    assert "S7comm response confirmed (PLC/CPU)" in result["evidence"]
    assert result["fingerprint_method"] == "nse_script"


def test_siemens_hmi_via_http_title():
    host = _host([(80, "HTTP")])
    fake_output = "SIMATIC HMI\nhttp-title: Panel Login\n"

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "Siemens"
    assert "SIMATIC HMI" in result["evidence"]
    assert any("Title: Panel Login" in e for e in result["evidence"])


def test_rockwell_enip_extracts_all_fields():
    host = _host([(44818, "EtherNet/IP")])
    fake_output = (
        "vendor: Rockwell Automation/Allen-Bradley\n"
        "productName: 1769-L33ER CompactLogix 5370\n"
        "revision: 33.011\n"
        "type: Programmable Logic Controller\n"
    )

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "Rockwell Automation/Allen-Bradley"
    assert result["model"] == "1769-L33ER CompactLogix 5370"
    assert result["firmware"] == "33.011"
    assert any("Programmable Logic Controller" in e for e in result["evidence"])


def test_br_sdm_confirmed_via_nse_probe():
    host = _host([(80, "HTTP")])

    fake_output = (
        "| br-info:\n"
        "|   Vendor: B&R Automation\n"
        "|   Component: System Diagnostics Manager (SDM) on port 80\n"
        "|_  Title (/sdm): System Diagnostics Manager\n"
    )

    with patch("subprocess.run", return_value=_run_result(fake_output)):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "B&R Automation"
    assert any("System Diagnostics Manager" in e for e in result["evidence"])
    assert any("BR-Info Title: System Diagnostics Manager" in e for e in result["evidence"])


def test_br_port_signature_fallback_when_nse_probe_fails():
    """No NSE confirmation available (or nothing returned) but a B&R-specific
    port is open -> should still produce an 'unconfirmed' vendor hint via
    port-signature evidence rather than nothing at all."""

    host = _host([(11169, "B&R ANSL")])

    with patch("subprocess.run", return_value=_run_result("")):
        result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] == "B&R Automation (unconfirmed - port signature only)"
    assert any("11169" in e for e in result["evidence"])
    assert result["fingerprint_method"] == "port_signature"


def test_no_ot_ports_produces_no_crash_and_no_vendor():
    host = _host([])

    result = fingerprinter._fingerprint_host(host, verbose=False)

    assert result["vendor"] is None
    assert result["evidence"] == []
    assert result["fingerprint_method"] == "none"


def test_subprocess_exception_is_caught_and_does_not_crash():
    host = _host([(102, "S7")])

    with patch("subprocess.run", side_effect=Exception("nmap not found")):
        result = fingerprinter._fingerprint_host(host, verbose=True)

    # should not raise, and host still comes back with defaults
    assert result["vendor"] is None
    assert result["firmware"] is None


def test_timeouts_are_passed_through_to_subprocess():
    host = _host([(102, "S7")])

    with patch("subprocess.run", return_value=_run_result("")) as mock_run:
        fingerprinter._fingerprint_host(host, verbose=False, script_timeout=99)

    assert mock_run.call_args.kwargs["timeout"] == 99


def test_fingerprint_runs_hosts_concurrently():
    """With N workers and simulated per-host latency, wall time should be
    close to one unit of latency, not N units."""

    def slow_fake(host, verbose=False, script_timeout=30):
        time.sleep(0.3)
        host["evidence"] = []
        host["vendor"] = "Test"
        host["model"] = None
        host["firmware"] = None
        return host

    data = [{"ip": f"10.0.0.{i}", "ot_ports": []} for i in range(10)]

    with patch.object(fingerprinter, "_fingerprint_host", side_effect=slow_fake):
        start = time.time()
        result = fingerprinter.fingerprint(data, verbose=False, workers=10)
        elapsed = time.time() - start

    assert elapsed < 1.0  # would be ~3s if run serially
    assert all(h["vendor"] == "Test" for h in result)


def test_fingerprint_empty_data_returns_empty():
    assert fingerprinter.fingerprint([], verbose=False) == []


def test_fingerprint_continues_after_one_host_crashes():
    def maybe_crash(host, verbose=False, script_timeout=30):
        if host["ip"] == "10.0.0.2":
            raise RuntimeError("boom")
        host["evidence"] = []
        host["vendor"] = "ok"
        host["model"] = None
        host["firmware"] = None
        return host

    data = [{"ip": "10.0.0.1", "ot_ports": []}, {"ip": "10.0.0.2", "ot_ports": []}]

    with patch.object(fingerprinter, "_fingerprint_host", side_effect=maybe_crash):
        result = fingerprinter.fingerprint(data, verbose=False, workers=2)

    assert len(result) == 2  # both hosts still present despite one crashing


def test_filtered_ports_do_not_trigger_fingerprint_or_evidence():
    """Regression test: filtered ports (firewalled/dropped) must NOT trigger
    active scripts or port-signature evidence."""
    host = {
        "ip": "10.0.0.1",
        "ot_ports": [
            {"port": 102, "protocol": "S7", "state": "filtered"},
            {"port": 50000, "protocol": "B&R SafeDESIGNER", "state": "filtered"},
            {"port": 11159, "protocol": "B&R PVI", "state": "filtered"},
            {"port": 44818, "protocol": "EtherNet/IP", "state": "filtered"},
        ],
    }
    with patch("subprocess.run") as mock_run:
        result = fingerprinter._fingerprint_host(host, verbose=False)
        # Subprocess should not even be called for filtered S7/ENIP ports
        mock_run.assert_not_called()

    assert result["vendor"] is None
    assert result["evidence"] == []
    assert result["fingerprint_method"] == "none"
