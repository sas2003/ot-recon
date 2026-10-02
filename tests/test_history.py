import json
from ot_recon.core import history


def _host(ip, ports=None, vendor=None, model=None, firmware=None, risks=None, severity=None):
    return {
        "ip": ip,
        "ot_ports": ports or [],
        "vendor": vendor,
        "model": model,
        "firmware": firmware,
        "risks": risks or [],
        "risk_severity": severity or "None",
    }


def test_save_and_load_snapshot_roundtrip(tmp_path):
    data = [_host("10.0.0.1")]

    path = history.save_snapshot(data, history_dir=tmp_path)
    assert path.exists()

    loaded = history.load_snapshot(path)
    assert loaded["hosts"] == data
    assert loaded["host_count"] == 1
    assert "timestamp" in loaded


def test_list_snapshots_returns_sorted_oldest_first(tmp_path):
    for name in ["20260101T000000Z.json", "20260103T000000Z.json", "20260102T000000Z.json"]:
        (tmp_path / name).write_text(json.dumps({"hosts": []}))

    result = history.list_snapshots(history_dir=tmp_path)
    assert [p.name for p in result] == [
        "20260101T000000Z.json", "20260102T000000Z.json", "20260103T000000Z.json"
    ]


def test_list_snapshots_empty_dir_returns_empty_list(tmp_path):
    assert history.list_snapshots(history_dir=tmp_path / "does_not_exist") == []


def test_diff_detects_new_and_removed_hosts():
    old_hosts = [_host("10.0.0.1"), _host("10.0.0.2")]
    new_hosts = [_host("10.0.0.1"), _host("10.0.0.3")]

    diff = history.diff_snapshots(old_hosts, new_hosts)

    assert diff["new_hosts"] == ["10.0.0.3"]
    assert diff["removed_hosts"] == ["10.0.0.2"]


def test_diff_detects_new_and_closed_ports():
    old_hosts = [_host("10.0.0.1", ports=[{"port": 80, "state": "open", "transport": "tcp"}])]
    new_hosts = [_host("10.0.0.1", ports=[
        {"port": 80, "state": "closed", "transport": "tcp"},
        {"port": 502, "state": "open", "transport": "tcp"},
    ])]

    diff = history.diff_snapshots(old_hosts, new_hosts)
    change = diff["host_changes"]["10.0.0.1"]

    assert change["new_ports"] == [(502, "tcp")]
    assert change["closed_ports"] == [(80, "tcp")]


def test_diff_detects_vendor_model_firmware_changes():
    old_hosts = [_host("10.0.0.1", vendor="Siemens", model="S7-1500", firmware="1.0.0")]
    new_hosts = [_host("10.0.0.1", vendor="Siemens", model="S7-1500", firmware="2.0.0")]

    diff = history.diff_snapshots(old_hosts, new_hosts)
    change = diff["host_changes"]["10.0.0.1"]

    assert change["firmware_change"] == ("1.0.0", "2.0.0")
    assert "vendor_change" not in change
    assert "model_change" not in change


def test_diff_detects_new_and_resolved_findings():
    finding_a = {"finding": "Modbus exposed", "severity": "High", "cve": None}
    finding_b = {"finding": "SNMP open", "severity": "Medium", "cve": None}

    old_hosts = [_host("10.0.0.1", risks=[finding_a])]
    new_hosts = [_host("10.0.0.1", risks=[finding_b])]

    diff = history.diff_snapshots(old_hosts, new_hosts)
    change = diff["host_changes"]["10.0.0.1"]

    assert change["new_findings"] == [finding_b]
    assert change["resolved_findings"] == [finding_a]


def test_diff_detects_severity_change():
    old_hosts = [_host("10.0.0.1", severity="Low")]
    new_hosts = [_host("10.0.0.1", severity="Critical")]

    diff = history.diff_snapshots(old_hosts, new_hosts)
    change = diff["host_changes"]["10.0.0.1"]

    assert change["severity_change"] == ("Low", "Critical")


def test_diff_unchanged_host_is_omitted():
    old_hosts = [_host("10.0.0.1", vendor="Siemens")]
    new_hosts = [_host("10.0.0.1", vendor="Siemens")]

    diff = history.diff_snapshots(old_hosts, new_hosts)

    assert diff["host_changes"] == {}
    assert diff["new_hosts"] == []
    assert diff["removed_hosts"] == []


def test_diff_no_changes_at_all_produces_empty_diff():
    hosts = [_host("10.0.0.1"), _host("10.0.0.2")]
    diff = history.diff_snapshots(hosts, hosts)

    assert diff == {"new_hosts": [], "removed_hosts": [], "host_changes": {}}
