# ot_recon/core/runner.py
#
# Single choke point for every external command OT-Recon runs (nmap, ip,
# ...). Two jobs:
#
#   1. Consistency - one place that actually calls subprocess.run, so the
#      tool can never shell out in a way the audit trail doesn't see.
#   2. Audit log - when configured, every command is appended to a JSON-
#      Lines file (output/audit/scan_<timestamp>.jsonl) with the exact argv,
#      purpose, timing and outcome. Asset owners and auditors routinely ask
#      "exactly what did your tool send to my network?" - this answers it.
#
# Auditing is opt-in via configure(); when unconfigured (e.g. in unit
# tests, library use) run() behaves exactly like subprocess.run.

import getpass
import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()
_state = {"audit_path": None, "command_count": 0}


def configure(audit_path):
    """Start auditing to `audit_path` (a Path). Creates parent dirs."""
    path = Path(audit_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        _state["audit_path"] = path
        _state["command_count"] = 0


def reset():
    """Stop auditing and clear counters (always call when a scan ends)."""
    with _lock:
        _state["audit_path"] = None
        _state["command_count"] = 0


def audit_path():
    return _state["audit_path"]


def command_count():
    return _state["command_count"]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def log_event(event, **fields):
    """Append one event to the audit log (no-op when not configured).
    Never raises - a full disk must not abort a scan midway."""

    path = _state["audit_path"]
    if path is None:
        return

    record = {"ts": _now(), "event": event, **fields}
    line = json.dumps(record, default=str)

    try:
        with _lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError:
        pass


def current_user():
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def run(cmd, purpose="", **kwargs):
    """subprocess.run(cmd, **kwargs) plus an audit record. Exceptions
    (timeouts, missing binaries) are logged and re-raised unchanged so
    callers keep their existing error handling."""

    argv = [str(a) for a in cmd]
    started = time.time()

    with _lock:
        _state["command_count"] += 1

    try:
        result = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        log_event("command", purpose=purpose, argv=argv, status="timeout",
                  duration_s=round(time.time() - started, 3))
        raise
    except Exception as e:
        log_event("command", purpose=purpose, argv=argv, status="error",
                  error=repr(e), duration_s=round(time.time() - started, 3))
        raise

    log_event("command", purpose=purpose, argv=argv, status="completed",
              returncode=getattr(result, "returncode", None),
              duration_s=round(time.time() - started, 3))
    return result
