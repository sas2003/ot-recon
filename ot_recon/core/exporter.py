# ot_recon/core/exporter.py
#
# Machine-readable export of scan results, for feeding into other tooling
# (SIEMs, spreadsheets, ticketing systems, diffing between runs, etc).
# The Rich console table stays the default output — these are opt-in via
# --format.

import csv
import json
from datetime import datetime, timezone


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sort_hosts_by_risk(hosts):
    """Sort hosts descending by risk_score (highest priority first)."""
    return sorted(hosts, key=lambda h: h.get("risk_score", 0), reverse=True)


def generate_network_summary(hosts):
    """Compute executive network-level metrics across all scanned hosts."""
    total_hosts = len(hosts)
    ot_hosts = sum(1 for h in hosts if h.get("type") and h.get("type") != "Unknown")

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    type_breakdown = {}
    vendor_breakdown = {}
    highest_score = 0

    for h in hosts:
        dev_type = h.get("type") or "Unknown"
        type_breakdown[dev_type] = type_breakdown.get(dev_type, 0) + 1

        vendor = h.get("vendor") or "Unknown"
        vendor_breakdown[vendor] = vendor_breakdown.get(vendor, 0) + 1

        score = h.get("risk_score", 0)
        if score > highest_score:
            highest_score = score

        for r in h.get("risks", []):
            sev = r.get("severity")
            if sev in severity_counts:
                severity_counts[sev] += 1

    return {
        "total_hosts": total_hosts,
        "ot_assets": ot_hosts,
        "max_risk_score": highest_score,
        "severity_counts": severity_counts,
        "type_distribution": type_breakdown,
        "vendor_distribution": vendor_breakdown,
    }


def export_json(data, path):
    """Write the full enriched/classified/risk-assessed dataset as JSON.
    Automatically includes an executive network_summary object and sorts
    hosts by risk_score descending.
    """
    sorted_hosts = _sort_hosts_by_risk(data)
    summary = generate_network_summary(data)

    payload = {
        "generated_at": _now_iso(),
        "host_count": len(data),
        "network_summary": summary,
        "hosts": sorted_hosts,
    }

    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    print(f"[+] JSON report written to {path}")


def export_csv(data, path):
    """Write a flat CSV: one row per (host, finding) pair, sorted by risk."""
    sorted_hosts = _sort_hosts_by_risk(data)

    fieldnames = [
        "ip", "type", "vendor", "model", "firmware",
        "confidence", "confidence_score", "detection_method", "evidence_based",
        "protocols", "risk_severity", "risk_score", "summary",
        "finding_severity", "finding", "remediation_priority",
        "impact", "likelihood", "recommendation", "related_ports",
        "cve", "advisory",
    ]

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for host in sorted_hosts:

            protocols = ", ".join(dict.fromkeys(
                p["protocol"] for p in host.get("ot_ports", [])
                if p.get("state", "open") == "open" and p.get("protocol")
            ))

            base_row = {
                "ip": host.get("ip", ""),
                "type": host.get("type", ""),
                "vendor": host.get("vendor") or "",
                "model": host.get("model") or "",
                "firmware": host.get("firmware") or "",
                "confidence": host.get("confidence", ""),
                "confidence_score": host.get("confidence_score", 0),
                "detection_method": host.get("detection_method", ""),
                "evidence_based": str(host.get("evidence_based", False)),
                "protocols": protocols,
                "risk_severity": host.get("risk_severity", ""),
                "risk_score": host.get("risk_score", 0),
                "summary": host.get("summary", ""),
            }

            risks = host.get("risks", [])

            if not risks:
                writer.writerow({
                    **base_row,
                    "finding_severity": "",
                    "finding": "",
                    "remediation_priority": "",
                    "impact": "",
                    "likelihood": "",
                    "recommendation": "",
                    "related_ports": "",
                    "cve": "",
                    "advisory": "",
                })
                continue

            for r in risks:
                rel_ports = ", ".join(str(p) for p in r.get("related_ports", []))
                writer.writerow({
                    **base_row,
                    "finding_severity": r.get("severity", ""),
                    "finding": r.get("finding", ""),
                    "remediation_priority": r.get("remediation_priority", ""),
                    "impact": r.get("impact", ""),
                    "likelihood": r.get("likelihood", ""),
                    "recommendation": r.get("recommendation", ""),
                    "related_ports": rel_ports,
                    "cve": r.get("cve") or "",
                    "advisory": r.get("advisory") or "",
                })

    print(f"[+] CSV report written to {path}")
