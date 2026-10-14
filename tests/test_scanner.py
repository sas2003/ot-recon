import subprocess
from unittest.mock import MagicMock, patch

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

    def fake_run_cmd(cmd, verbose=False, **kw):
        # Simulate nmap writing its XML output file
        xml_path.write_text(DISCOVERY_XML_UP_AND_DOWN)

    # get_local_ips is mocked so this test never shells out to the real
    # `ip` command or opens a real socket - results must not depend on
    # whichever machine happens to be running the test suite.
    with patch.object(scanner, "get_local_ips", return_value=set()), \
         patch.object(scanner, "run_cmd", side_effect=fake_run_cmd) as mock_run:
        hosts = scanner.discover_hosts("10.0.0.0/24", verbose=False)

    assert hosts == ["10.0.0.1", "10.0.0.3"]
    cmd = mock_run.call_args[0][0]
    assert "-sn" in cmd
    assert "10.0.0.0/24" in cmd


def _discover_with_fake_xml(tmp_path, monkeypatch, local_ips, **kwargs):
    """Helper: run discover_hosts against the shared fake discovery XML
    (10.0.0.1 and 10.0.0.3 up) with a controlled set of 'local' IPs."""

    xml_path = tmp_path / "discovery.xml"
    monkeypatch.setattr(scanner, "DISCOVERY_XML", xml_path)

    def fake_run_cmd(cmd, verbose=False, **kw):
        xml_path.write_text(DISCOVERY_XML_UP_AND_DOWN)

    with patch.object(scanner, "get_local_ips", return_value=local_ips), \
         patch.object(scanner, "run_cmd", side_effect=fake_run_cmd) as mock_run:
        hosts = scanner.discover_hosts("10.0.0.0/24", **kwargs)

    return hosts, mock_run.call_args[0][0]


def test_discover_hosts_passes_local_ips_to_nmap_exclude(tmp_path, monkeypatch):
    hosts, cmd = _discover_with_fake_xml(tmp_path, monkeypatch, {"10.0.0.99"})

    assert "--exclude" in cmd
    assert cmd[cmd.index("--exclude") + 1] == "10.0.0.99"


def test_discover_hosts_joins_multiple_local_ips_for_exclude(tmp_path, monkeypatch):
    """Multi-homed machine: every local address goes into one --exclude
    list, sorted so the command is deterministic."""

    hosts, cmd = _discover_with_fake_xml(tmp_path, monkeypatch, {"10.0.0.50", "10.0.0.5"})

    assert cmd[cmd.index("--exclude") + 1] == "10.0.0.5,10.0.0.50"


def test_discover_hosts_filters_self_from_results_as_safety_net(tmp_path, monkeypatch):
    """Even if nmap's --exclude somehow misses it (here the fake nmap
    output still reports 10.0.0.3 as up), the Python-side filter must
    drop the machine's own IP from the returned host list."""

    hosts, _cmd = _discover_with_fake_xml(tmp_path, monkeypatch, {"10.0.0.3"})

    assert hosts == ["10.0.0.1"]
    assert "10.0.0.3" not in hosts


def test_discover_hosts_exclude_self_false_skips_exclusion_entirely(tmp_path, monkeypatch):
    """--include-self path: no --exclude flag, no filtering, and we should
    not even bother detecting local IPs."""

    xml_path = tmp_path / "discovery.xml"
    monkeypatch.setattr(scanner, "DISCOVERY_XML", xml_path)

    def fake_run_cmd(cmd, verbose=False, **kw):
        xml_path.write_text(DISCOVERY_XML_UP_AND_DOWN)

    with patch.object(scanner, "get_local_ips", return_value={"10.0.0.3"}) as mock_ips, \
         patch.object(scanner, "run_cmd", side_effect=fake_run_cmd) as mock_run:
        hosts = scanner.discover_hosts("10.0.0.0/24", exclude_self=False)

    mock_ips.assert_not_called()
    assert "--exclude" not in mock_run.call_args[0][0]
    assert hosts == ["10.0.0.1", "10.0.0.3"]  # self NOT filtered out


def test_discover_hosts_no_exclude_flag_when_no_local_ips_detected(tmp_path, monkeypatch):
    """Detection failed entirely (empty set) - must degrade to a normal
    scan, not pass an empty --exclude argument that would make nmap error."""

    hosts, cmd = _discover_with_fake_xml(tmp_path, monkeypatch, set())

    assert "--exclude" not in cmd
    assert hosts == ["10.0.0.1", "10.0.0.3"]


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


# --- pacing, do-not-scan list, stale-artifact cleanup ---

def test_discovery_cmd_includes_profile_pacing_flags():
    cmd = scanner.build_discovery_cmd("10.0.0.0/24", pacing=["-T2", "--scan-delay", "200ms"])
    assert cmd[:2] == ["nmap", "-sn"]
    assert "-T2" in cmd and cmd[cmd.index("--scan-delay") + 1] == "200ms"
    assert cmd[-1] == "10.0.0.0/24"          # target stays last, never mistaken for an option value


def test_tcp_scan_pacing_replaces_legacy_timing():
    cmd = scanner.build_tcp_scan_cmd(["10.0.0.1"], "102", tcp_timing="T5",
                                     pacing=["-T2", "--max-retries", "1"])
    assert "-T2" in cmd and "-T5" not in cmd      # never both timing flags
    assert cmd[cmd.index("--max-retries") + 1] == "1"
    assert cmd[-1] == "10.0.0.1"


def test_tcp_scan_legacy_timing_still_works_without_pacing():
    cmd = scanner.build_tcp_scan_cmd(["10.0.0.1"], "102", tcp_timing="T3")
    assert "-T3" in cmd


def test_udp_scan_pacing():
    cmd = scanner.build_udp_scan_cmd(["10.0.0.1"], "161", pacing=["-T2"])
    assert "-sU" in cmd and "-T2" in cmd and "-T4" not in cmd


def test_user_exclude_list_goes_to_nmap_and_is_filtered_from_results(tmp_path, monkeypatch):
    hosts, cmd = _discover_with_fake_xml(
        tmp_path, monkeypatch, set(), exclude=["10.0.0.3"]
    )
    assert cmd[cmd.index("--exclude") + 1] == "10.0.0.3"
    assert hosts == ["10.0.0.1"]              # fake nmap still reported .3 up; Python filter drops it


def test_exclude_list_accepts_cidr_and_filters_by_membership(tmp_path, monkeypatch):
    hosts, cmd = _discover_with_fake_xml(
        tmp_path, monkeypatch, set(), exclude=["10.0.0.0/30"]   # covers .0-.3
    )
    assert hosts == []                        # both .1 and .3 fall inside the excluded /30


def test_self_and_user_excludes_are_combined_into_one_flag(tmp_path, monkeypatch):
    _hosts, cmd = _discover_with_fake_xml(
        tmp_path, monkeypatch, {"10.0.0.99"}, exclude=["10.0.0.50"]
    )
    assert sorted(cmd[cmd.index("--exclude") + 1].split(",")) == ["10.0.0.50", "10.0.0.99"]


def test_exclude_applies_even_when_exclude_self_is_false(tmp_path, monkeypatch):
    """--include-self lifts only the *self* exclusion, never the operator's
    explicit do-not-scan list."""
    hosts, cmd = _discover_with_fake_xml(
        tmp_path, monkeypatch, {"10.0.0.1"}, exclude_self=False, exclude=["10.0.0.3"]
    )
    assert hosts == ["10.0.0.1"]
    assert cmd[cmd.index("--exclude") + 1] == "10.0.0.3"


def test_clear_artifacts_removes_previous_run_outputs(tmp_path, monkeypatch):
    for name in ("DISCOVERY_XML", "SCAN_XML", "UDP_SCAN_XML"):
        f = tmp_path / f"{name}.xml"
        f.write_text("<stale/>")
        monkeypatch.setattr(scanner, name, f)

    scanner.clear_artifacts()

    for name in ("DISCOVERY_XML", "SCAN_XML", "UDP_SCAN_XML"):
        assert not (tmp_path / f"{name}.xml").exists()


def test_clear_artifacts_is_fine_when_nothing_exists(tmp_path, monkeypatch):
    for name in ("DISCOVERY_XML", "SCAN_XML", "UDP_SCAN_XML"):
        monkeypatch.setattr(scanner, name, tmp_path / "nope.xml")
    scanner.clear_artifacts()   # must not raise


def test_scanner_commands_go_through_the_audited_runner():
    """Every nmap invocation must pass through runner.run so it reaches
    the audit log - a direct subprocess.run would be invisible to it."""
    with patch.object(scanner.runner, "run") as mock_run:
        scanner.run_cmd(["nmap", "-sn", "x"], verbose=False, purpose="discovery")

    assert mock_run.call_args.kwargs["purpose"] == "discovery"


# --- get_nmap_version (recorded in the report so findings tie to a scanner build) ---

def _fake_version_run(stdout):
    r = MagicMock()
    r.stdout = stdout
    return r


def test_get_nmap_version_parses_real_banner():
    banner = "Nmap version 7.94SVN ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\n"
    with patch.object(scanner.runner, "run", return_value=_fake_version_run(banner)) as m:
        assert scanner.get_nmap_version() == "7.94SVN"
    assert m.call_args.kwargs["purpose"] == "version"


def test_get_nmap_version_none_when_nmap_missing():
    with patch.object(scanner.runner, "run", side_effect=FileNotFoundError("nmap")):
        assert scanner.get_nmap_version() is None


def test_get_nmap_version_none_on_unrecognised_output():
    with patch.object(scanner.runner, "run", return_value=_fake_version_run("something else\n")):
        assert scanner.get_nmap_version() is None


def test_get_nmap_version_none_on_timeout():
    import subprocess
    with patch.object(scanner.runner, "run", side_effect=subprocess.TimeoutExpired("nmap", 10)):
        assert scanner.get_nmap_version() is None
