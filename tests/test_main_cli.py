import sys
import pytest
from unittest.mock import patch

from ot_recon import main as main_module


def _run_main(argv, tmp_path):
    """Run main.main() with sys.argv patched, and every pipeline stage
    function mocked so no real nmap/network calls happen. Returns the mock
    objects so tests can assert on call args.
    """

    mocks = {}

    with patch.object(sys, "argv", ["ot-recon"] + argv), \
         patch.object(main_module, "discover_hosts", return_value=["10.0.0.1"]) as m_discover, \
         patch.object(main_module, "scan_live_hosts") as m_scan, \
         patch.object(main_module, "parse_results", return_value=[{"ip": "10.0.0.1", "ports": []}]) as m_parse, \
         patch.object(main_module, "enrich", side_effect=lambda d: d) as m_enrich, \
         patch.object(main_module, "fingerprint", side_effect=lambda d, *a, **kw: d) as m_fp, \
         patch.object(main_module, "classify", side_effect=lambda d: d) as m_classify, \
         patch.object(main_module, "assess_risk", side_effect=lambda d: d) as m_risk, \
         patch.object(main_module, "generate_report") as m_report, \
         patch.object(main_module, "export_json") as m_json, \
         patch.object(main_module, "export_csv") as m_csv, \
         patch.object(main_module.history, "save_snapshot") as m_snapshot, \
         patch.object(main_module, "OUTPUT_DIR", tmp_path):

        main_module.main()

        mocks.update(discover=m_discover, scan=m_scan, parse=m_parse, enrich=m_enrich,
                     fp=m_fp, classify=m_classify, risk=m_risk, report=m_report,
                     export_json=m_json, export_csv=m_csv, snapshot=m_snapshot)

    return mocks


def test_scan_with_no_target_errors_via_argparse(capsys):
    """target is a required positional on the scan subparser now, so
    argparse itself rejects a missing target with a usage error and
    SystemExit(2), rather than a custom message."""

    with patch.object(sys, "argv", ["ot-recon", "scan"]), \
         patch.object(main_module, "discover_hosts") as m_discover:
        with pytest.raises(SystemExit):
            main_module.main()

    m_discover.assert_not_called()
    assert "usage" in capsys.readouterr().err.lower()


def test_unknown_command_errors_via_argparse(capsys):
    with patch.object(sys, "argv", ["ot-recon", "bogus"]):
        with pytest.raises(SystemExit):
            main_module.main()

    assert "invalid choice" in capsys.readouterr().err.lower()


def test_no_command_prints_help(capsys):
    with patch.object(sys, "argv", ["ot-recon"]):
        main_module.main()

    assert "usage" in capsys.readouterr().out.lower()


def test_default_scan_runs_full_pipeline_in_order(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)

    mocks["discover"].assert_called_once()
    mocks["scan"].assert_called_once()
    mocks["parse"].assert_called_once()
    mocks["enrich"].assert_called_once()
    mocks["fp"].assert_called_once()
    mocks["classify"].assert_called_once()
    mocks["risk"].assert_called_once()
    mocks["report"].assert_called_once()

    # default format is 'table' -> no export calls
    mocks["export_json"].assert_not_called()
    mocks["export_csv"].assert_not_called()


def test_workers_cli_flag_overrides_config(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--workers", "42"], tmp_path)

    _, kwargs = mocks["fp"].call_args
    assert kwargs["workers"] == 42


def test_workers_falls_back_to_config_when_unset(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)

    _, kwargs = mocks["fp"].call_args
    assert kwargs["workers"] == 10  # data/config.yaml default


def test_format_json_triggers_json_export_only(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "json"], tmp_path)

    mocks["export_json"].assert_called_once()
    mocks["export_csv"].assert_not_called()


def test_format_all_triggers_both_exports(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--format", "all"], tmp_path)

    mocks["export_json"].assert_called_once()
    mocks["export_csv"].assert_called_once()


def test_udp_flag_is_forwarded_to_scan_live_hosts(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--udp"], tmp_path)

    _, kwargs = mocks["scan"].call_args
    assert kwargs["udp"] is True


def test_site_config_overrides_are_respected(tmp_path):
    site_yaml = tmp_path / "site.yaml"
    site_yaml.write_text("fingerprint:\n  workers: 77\n")

    mocks = _run_main(["scan", "10.0.0.0/24", "--config", str(site_yaml)], tmp_path)

    _, kwargs = mocks["fp"].call_args
    assert kwargs["workers"] == 77


def test_scan_saves_history_snapshot_by_default(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24"], tmp_path)
    mocks["snapshot"].assert_called_once()


def test_no_history_flag_skips_snapshot(tmp_path):
    mocks = _run_main(["scan", "10.0.0.0/24", "--no-history"], tmp_path)
    mocks["snapshot"].assert_not_called()


def test_diff_with_fewer_than_two_snapshots_prints_message(tmp_path, capsys):
    with patch.object(sys, "argv", ["ot-recon", "diff"]), \
         patch.object(main_module.history, "list_snapshots", return_value=[]):
        main_module.main()

    assert "at least 2 saved snapshots" in capsys.readouterr().out


def test_diff_compares_two_most_recent_snapshots_by_default(tmp_path):
    old_snap = {"timestamp": "old", "hosts": [{"ip": "10.0.0.1", "ot_ports": [], "risks": []}]}
    new_snap = {"timestamp": "new", "hosts": [{"ip": "10.0.0.1", "ot_ports": [], "risks": []},
                                               {"ip": "10.0.0.2", "ot_ports": [], "risks": []}]}

    fake_paths = [tmp_path / "old.json", tmp_path / "new.json"]

    with patch.object(sys, "argv", ["ot-recon", "diff"]), \
         patch.object(main_module.history, "list_snapshots", return_value=fake_paths), \
         patch.object(main_module.history, "load_snapshot",
                       side_effect=lambda p: old_snap if p == fake_paths[0] else new_snap), \
         patch.object(main_module, "generate_diff_report") as m_diff_report:
        main_module.main()

    m_diff_report.assert_called_once()
    diff_arg = m_diff_report.call_args[0][0]
    assert diff_arg["new_hosts"] == ["10.0.0.2"]


def test_diff_with_explicit_from_and_to(tmp_path):
    old_snap = {"timestamp": "old", "hosts": []}
    new_snap = {"timestamp": "new", "hosts": []}

    old_path = tmp_path / "a.json"
    new_path = tmp_path / "b.json"

    with patch.object(sys, "argv", ["ot-recon", "diff", "--from", str(old_path), "--to", str(new_path)]), \
         patch.object(main_module.history, "load_snapshot",
                       side_effect=lambda p: old_snap if str(p) == str(old_path) else new_snap) as m_load, \
         patch.object(main_module, "generate_diff_report") as m_diff_report:
        main_module.main()

    assert m_load.call_count == 2
    m_diff_report.assert_called_once()


def test_history_command_with_no_snapshots(capsys):
    with patch.object(sys, "argv", ["ot-recon", "history"]), \
         patch.object(main_module.history, "list_snapshots", return_value=[]):
        main_module.main()

    assert "No saved snapshots" in capsys.readouterr().out


def test_history_command_lists_snapshots(tmp_path, capsys):
    snap = {"timestamp": "20260101T000000Z", "host_count": 3, "hosts": [
        {"risk_severity": "Critical"}, {"risk_severity": "Low"}, {"risk_severity": "None"},
    ]}
    fake_path = tmp_path / "snap.json"

    with patch.object(sys, "argv", ["ot-recon", "history"]), \
         patch.object(main_module.history, "list_snapshots", return_value=[fake_path]), \
         patch.object(main_module.history, "load_snapshot", return_value=snap):
        main_module.main()

    out = capsys.readouterr().out
    assert "20260101T000000Z" in out
    assert "3 host(s)" in out
    assert "1 Critical/High" in out
