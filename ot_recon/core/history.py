# ot_recon/core/history.py
#
# Persists each scan's fully enriched/classified/risk-assessed dataset as a
# timestamped JSON snapshot, and diffs two snapshots against each other so
# asset changes (new/removed hosts, new/closed ports, vendor or firmware
# changes, new or resolved risk findings) are visible across runs. This is
# the groundwork for the "asset inventory over time" item on the roadmap.

import json
from datetime import datetime, timezone
from pathlib import Path

from ot_recon.core.paths import OUTPUT_DIR

HISTORY_DIR = OUTPUT_DIR / "history"

# Snapshot filenames sort correctly as strings because of this format.
_TS_FORMAT = "%Y%m%dT%H%M%SZ"


def _now_ts():
    return datetime.now(timezone.utc).strftime(_TS_FORMAT)


def save_snapshot(data, history_dir=None):
    """Persist the current scan's dataset as a timestamped JSON snapshot.
    Returns the path written to."""

    history_dir = Path(history_dir) if history_dir else HISTORY_DIR
    history_dir.mkdir(parents=True, exist_ok=True)

    ts = _now_ts()
    path = history_dir / f"{ts}.json"

    payload = {
        "timestamp": ts,
        "host_count": len(data),
        "hosts": data,
    }

    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    print(f"[+] Snapshot saved to {path}")
    return path


def list_snapshots(history_dir=None):
    """Return all snapshot paths, oldest first."""

    history_dir = Path(history_dir) if history_dir else HISTORY_DIR

    if not history_dir.exists():
        return []

    return sorted(history_dir.glob("*.json"))


def load_snapshot(path):
    with open(path, "r") as f:
        payload = json.load(f)

    return payload


def _index_by_ip(hosts):
    return {h["ip"]: h for h in hosts}


def _finding_key(finding):
    """Identity for comparing findings across snapshots - text + CVE id,
    since severity/order aren't part of what defines 'the same finding'."""

    return (finding.get("finding", ""), finding.get("cve") or "")


def diff_snapshots(old_hosts, new_hosts):
    """Compare two host-list datasets (as produced by the pipeline) and
    return a structured diff:

    {
      "new_hosts": [ip, ...],
      "removed_hosts": [ip, ...],
      "host_changes": {
          ip: {
              "new_ports": [...], "closed_ports": [...],
              "vendor_change": (old, new) | None,
              "model_change": (old, new) | None,
              "firmware_change": (old, new) | None,
              "new_findings": [finding, ...],
              "resolved_findings": [finding, ...],
              "severity_change": (old, new) | None,
          },
          ...
      }
    }

    Only hosts present in both snapshots and with at least one detected
    change appear in host_changes - unchanged hosts are omitted entirely
    to keep the diff focused.
    """

    old_by_ip = _index_by_ip(old_hosts)
    new_by_ip = _index_by_ip(new_hosts)

    old_ips = set(old_by_ip)
    new_ips = set(new_by_ip)

    new_host_ips = sorted(new_ips - old_ips)
    removed_host_ips = sorted(old_ips - new_ips)

    host_changes = {}

    for ip in sorted(old_ips & new_ips):

        old_host = old_by_ip[ip]
        new_host = new_by_ip[ip]

        change = {}

        old_ports = {
            (p["port"], p.get("transport", "tcp"))
            for p in old_host.get("ot_ports", []) if p.get("state") == "open"
        }
        new_ports = {
            (p["port"], p.get("transport", "tcp"))
            for p in new_host.get("ot_ports", []) if p.get("state") == "open"
        }

        added_ports = sorted(new_ports - old_ports)
        closed_ports = sorted(old_ports - new_ports)

        if added_ports:
            change["new_ports"] = added_ports

        if closed_ports:
            change["closed_ports"] = closed_ports

        for field in ("vendor", "model", "firmware"):
            old_val = old_host.get(field)
            new_val = new_host.get(field)

            if old_val != new_val:
                change[f"{field}_change"] = (old_val, new_val)

        old_findings = {_finding_key(f): f for f in old_host.get("risks", [])}
        new_findings = {_finding_key(f): f for f in new_host.get("risks", [])}

        new_finding_keys = set(new_findings) - set(old_findings)
        resolved_finding_keys = set(old_findings) - set(new_findings)

        if new_finding_keys:
            change["new_findings"] = [new_findings[k] for k in new_finding_keys]

        if resolved_finding_keys:
            change["resolved_findings"] = [old_findings[k] for k in resolved_finding_keys]

        old_sev = old_host.get("risk_severity")
        new_sev = new_host.get("risk_severity")

        if old_sev != new_sev:
            change["severity_change"] = (old_sev, new_sev)

        if change:
            host_changes[ip] = change

    return {
        "new_hosts": new_host_ips,
        "removed_hosts": removed_host_ips,
        "host_changes": host_changes,
    }
