import subprocess
from unittest.mock import patch

from ot_recon.core import scanner


DISCOVERY_XML_UP_AND_DOWN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.3" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_parse_discovery_only_returns_up_hosts(tmp_path, monkeypatch):
    xml_path = tmp_path / "discovery.xml"
    xml_path.write_text(DISCOVERY_XML_UP_AND_DOWN)

    monkeypatch.setattr(scanner, "DISCOVERY_XML", xml_path)

    hosts = scanner.parse_discovery()

    assert hosts == ["10.0.0.1", "10.0.0.3"]


def test_parse_discovery_missing_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "DISCOVERY_XML", tmp_path / "missing.xml")
    assert scanner.parse_discovery() == []


def test_parse_discovery_invalid_xml_returns_empty(tmp_path, monkeypatch):
    bad_path = tmp_path / "bad.xml"
    bad_path.write_text("not xml <<<")
    monkeypatch.setattr(scanner, "DISCOVERY_XML", bad_path)

    assert scanner.parse_discovery() == []


def test_discover_hosts_invokes_nmap_and_parses_result(tmp_path, monkeypatch):
    xml_path = tmp_path / "discovery.xml"
    monkeypatch.setattr(scanner, "DISCOVERY_XML", xml_path)

    def fake_run_cmd(cmd, verbose=False):
        # Simulate nmap writing its XML output file
        xml_path.write_text(DISCOVERY_XML_UP_AND_DOWN)

    with patch.object(scanner, "run_cmd", side_effect=fake_run_cmd) as mock_run:
        hosts = scanner.discover_hosts("10.0.0.0/24", verbose=False)

    assert hosts == ["10.0.0.1", "10.0.0.3"]
    cmd = mock_run.call_args[0][0]
    assert "-sn" in cmd
    assert "10.0.0.0/24" in cmd


def test_run_cmd_suppresses_output_when_not_verbose():
    with patch("subprocess.run") as mock_run:
        scanner.run_cmd(["echo", "hi"], verbose=False)

    _, kwargs = mock_run.call_args
    assert kwargs.get("stdout") == subprocess.DEVNULL
    assert kwargs.get("stderr") == subprocess.DEVNULL


def test_run_cmd_shows_output_when_verbose():
    with patch("subprocess.run") as mock_run:
        scanner.run_cmd(["echo", "hi"], verbose=True)

    args, kwargs = mock_run.call_args
    assert "stdout" not in kwargs


def test_scan_live_hosts_uses_defaults_when_no_config_passed():
    with patch.object(scanner, "run_cmd") as mock_run:
        scanner.scan_live_hosts(["10.0.0.5"], verbose=False, udp=False)

    cmd = mock_run.call_args[0][0]
    assert "nmap" in cmd
    assert "-T5" in cmd
    assert scanner.OT_TCP_PORTS in cmd
    assert "-sT" in cmd


def test_scan_live_hosts_respects_configured_ports_and_timing():
    with patch.object(scanner, "run_cmd") as mock_run:
        scanner.scan_live_hosts(
            ["10.0.0.5"], verbose=False, udp=False,
            tcp_ports="102,44818", tcp_timing="T2",
        )

    cmd = mock_run.call_args[0][0]
    assert "-T2" in cmd
    assert "102,44818" in cmd


def test_scan_live_hosts_no_hosts_does_not_call_nmap():
    with patch.object(scanner, "run_cmd") as mock_run:
        scanner.scan_live_hosts([], verbose=False)

    mock_run.assert_not_called()


def test_scan_live_hosts_triggers_udp_scan_when_requested():
    with patch.object(scanner, "run_cmd"), \
         patch.object(scanner, "scan_udp_ports") as mock_udp:
        scanner.scan_live_hosts(["10.0.0.5"], verbose=False, udp=True,
                                 udp_ports="161", udp_timing="T2")

    mock_udp.assert_called_once()
    _, kwargs = mock_udp.call_args
    assert kwargs.get("udp_ports") == "161" or "161" in mock_udp.call_args[0]


def test_scan_live_hosts_does_not_trigger_udp_scan_by_default():
    with patch.object(scanner, "run_cmd"), \
         patch.object(scanner, "scan_udp_ports") as mock_udp:
        scanner.scan_live_hosts(["10.0.0.5"], verbose=False)

    mock_udp.assert_not_called()


def test_scan_udp_ports_handles_permission_failure_gracefully():
    """A non-root UDP scan should fail cleanly (nmap returns non-zero),
    not raise, since -sU commonly needs root."""

    fake_result = type("R", (), {"returncode": 1, "stdout": "", "stderr": "requires root"})()

    with patch("subprocess.run", return_value=fake_result) as mock_run:
        scanner.scan_udp_ports(["10.0.0.5"], verbose=False)

    mock_run.assert_called_once()


def test_scan_udp_ports_uses_configured_values():
    fake_result = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch("subprocess.run", return_value=fake_result) as mock_run:
        scanner.scan_udp_ports(["10.0.0.5"], verbose=False, udp_ports="2222", udp_timing="T1")

    cmd = mock_run.call_args[0][0]
    assert "-T1" in cmd
    assert "2222" in cmd
    assert "-sU" in cmd
