import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from ot_recon.core import runner


@pytest.fixture(autouse=True)
def _clean_runner_state():
    runner.reset()
    yield
    runner.reset()


def _lines(path):
    return [json.loads(l) for l in path.read_text().splitlines()]


def test_run_without_audit_behaves_like_subprocess_run(tmp_path):
    fake = MagicMock(returncode=0)
    with patch("subprocess.run", return_value=fake) as mock_run:
        result = runner.run(["echo", "hi"], purpose="t", capture_output=True)

    assert result is fake
    mock_run.assert_called_once_with(["echo", "hi"], capture_output=True)
    assert runner.audit_path() is None


def test_audited_run_records_argv_purpose_and_outcome(tmp_path):
    log = tmp_path / "audit" / "scan.jsonl"   # parent dir must be created
    runner.configure(log)

    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        runner.run(["nmap", "-sn", "10.0.0.0/24"], purpose="discovery")

    [rec] = _lines(log)
    assert rec["event"] == "command"
    assert rec["argv"] == ["nmap", "-sn", "10.0.0.0/24"]
    assert rec["purpose"] == "discovery"
    assert rec["status"] == "completed" and rec["returncode"] == 0
    assert "ts" in rec and "duration_s" in rec
    assert runner.command_count() == 1


def test_timeout_is_logged_and_reraised():
    runner.configure(__import__("pathlib").Path(__import__("tempfile").mkdtemp()) / "a.jsonl")
    log = runner.audit_path()

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 5)):
        with pytest.raises(subprocess.TimeoutExpired):
            runner.run(["nmap"], purpose="fingerprint")

    assert _lines(log)[0]["status"] == "timeout"


def test_errors_are_logged_and_reraised(tmp_path):
    runner.configure(tmp_path / "a.jsonl")

    with patch("subprocess.run", side_effect=FileNotFoundError("nmap")):
        with pytest.raises(FileNotFoundError):
            runner.run(["nmap"], purpose="discovery")

    rec = _lines(tmp_path / "a.jsonl")[0]
    assert rec["status"] == "error" and "FileNotFoundError" in rec["error"]


def test_log_event_is_noop_when_unconfigured(tmp_path):
    before = set(tmp_path.rglob("*"))
    runner.log_event("scan_start", target="x")   # must not raise or create files
    assert set(tmp_path.rglob("*")) == before


def test_log_event_never_raises_on_unwritable_path(tmp_path):
    runner.configure(tmp_path / "a.jsonl")
    runner._state["audit_path"] = tmp_path  # a directory: open(..., "a") fails
    runner.log_event("x")  # swallowed - a full/readonly disk must not abort a scan


def test_reset_stops_auditing(tmp_path):
    log = tmp_path / "a.jsonl"
    runner.configure(log)
    runner.reset()
    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        runner.run(["echo"], purpose="x")
    assert not log.exists()


def test_non_string_argv_items_are_stringified_in_log(tmp_path):
    runner.configure(tmp_path / "a.jsonl")
    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        runner.run(["nmap", tmp_path / "x.nse"], purpose="p")  # a Path in argv
    assert isinstance(_lines(tmp_path / "a.jsonl")[0]["argv"][1], str)


def test_concurrent_logging_produces_whole_lines(tmp_path):
    """Fingerprinting logs from many threads at once; every line must stay
    a complete, parseable JSON record."""
    import threading
    runner.configure(tmp_path / "a.jsonl")

    def worker(i):
        for j in range(25):
            runner.log_event("command", purpose=f"t{i}", argv=["x"] * 20)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in threads]; [t.join() for t in threads]

    assert len(_lines(tmp_path / "a.jsonl")) == 8 * 25
