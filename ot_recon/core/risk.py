# ot_recon/core/risk.py
#
# Risk engine v2: findings are structured dicts with severity levels,
# impact/likelihood assessments, actionable remediation recommendations,
# and correlation with local CVE records. Computes a quantitative risk_score
# (0-100) taking into account device criticality weighting.

from ot_recon.core import cve as cve_engine

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

PRIORITY_MAP = {
    "Critical": "P1",
    "High": "P2",
    "Medium": "P3",
    "Low": "P4",
    "Info": "P5",
}

DEFAULT_IMPACT = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Low",
}

DEFAULT_LIKELIHOOD = {
    "Critical": "High",
    "High": "Medium",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Low",
}

SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 20,
    "Medium": 10,
    "Low": 3,
    "Info": 0,
}

ASSET_MULTIPLIERS = {
    "Safety PLC": 1.3,
    "PLC": 1.2,
    "PLC/CPU": 1.2,
    "HMI": 1.1,
}


def _finding(
    text,
    severity,
    cve_id=None,
    advisory=None,
    impact=None,
    likelihood=None,
    recommendation=None,
    remediation_priority=None,
    related_ports=None,
):
    return {
        "finding": text,
        "severity": severity,
        "cve": cve_id,
        "advisory": advisory,
        "impact": impact or DEFAULT_IMPACT.get(severity, "Low"),
        "likelihood": likelihood or DEFAULT_LIKELIHOOD.get(severity, "Low"),
        "recommendation": recommendation or "Review configuration and limit network access.",
        "remediation_priority": remediation_priority or PRIORITY_MAP.get(severity, "P4"),
        "related_ports": related_ports or [],
    }


def _highest_severity(findings):
    if not findings:
        return None

    return min(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 99))["severity"]


def _calculate_risk_score(findings, host_type=None):
    """Compute a normalized 0-100 risk score based on finding severities and
    the criticality of the asset type."""
    if not findings:
        return 0

    raw = sum(SEVERITY_WEIGHTS.get(f.get("severity"), 0) for f in findings)
    mult = ASSET_MULTIPLIERS.get(host_type, 1.0)
    return min(100, round(raw * mult))


def _generate_host_summary(host, findings, risk_score):
    """Generate a concise, human-readable risk summary for a host."""
    if not findings:
        return "No security risks identified on exposed ports or services."

    sev_counts = {}
    for f in findings:
        s = f.get("severity", "Info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    counts_str = ", ".join(
        f"{c} {s}"
        for s, c in sorted(
            sev_counts.items(), key=lambda x: SEVERITY_RANK.get(x[0], 99)
        )
    )

    top_finding = min(
        findings, key=lambda f: SEVERITY_RANK.get(f.get("severity"), 99)
    )
    top_text = top_finding.get("finding", "")
    highest_sev = top_finding.get("severity", "Info")

    vendor = host.get("vendor") or "Generic"
    dev_type = host.get("type") or "Device"

    return (
        f"{vendor} {dev_type} assessed with {highest_sev} severity (risk score: {risk_score}/100) "
        f"across {len(findings)} finding(s) ({counts_str}). "
        f"Primary concern: {top_text}. Recommended action: {top_finding.get('recommendation')}"
    )


def assess_risk(data):
    for host in data:
        findings = []

        ot_ports = host.get("ot_ports", [])

        open_by_protocol = {
            p["protocol"] for p in ot_ports if p["state"] == "open"
        }
        open_ports = {p["port"] for p in ot_ports if p["state"] == "open"}

        # 🔸 OT protocol risks
        if "Modbus" in open_by_protocol:
            findings.append(_finding(
                "Modbus exposed (no authentication)",
                "High",
                impact="High",
                likelihood="High",
                recommendation="Restrict Modbus port 502 to authorized engineering/SCADA stations via firewall/VLAN; implement deep packet inspection (DPI) if supported.",
                remediation_priority="P2",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "Modbus" and p.get("state") == "open"],
            ))

        if "S7" in open_by_protocol:
            findings.append(_finding(
                "Siemens S7 exposed",
                "High",
                impact="Critical",
                likelihood="Medium",
                recommendation="Isolate port 102 from untrusted networks; enable S7-1500/1200 secure communication and disable legacy PUT/GET access.",
                remediation_priority="P2",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "S7" and p.get("state") == "open"],
            ))

        if "EtherNet/IP" in open_by_protocol:
            findings.append(_finding(
                "EtherNet/IP exposed",
                "High",
                impact="High",
                likelihood="Medium",
                recommendation="Segment port 44818 behind industrial firewalls; enforce CIP Security (TLS/DTLS) if supported by the controller.",
                remediation_priority="P2",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "EtherNet/IP" and p.get("state") == "open"],
            ))

        if "EtherNet/IP-IO" in open_by_protocol:
            findings.append(_finding(
                "EtherNet/IP implicit I/O exposed (UDP, cyclic control traffic)",
                "Medium",
                impact="High",
                likelihood="Low",
                recommendation="Restrict UDP port 2222 to the local I/O subnet/VLAN; do not route cyclic I/O across general plant networks.",
                remediation_priority="P3",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "EtherNet/IP-IO" and p.get("state") == "open"],
            ))

        if "DNP3" in open_by_protocol:
            findings.append(_finding(
                "DNP3 exposed",
                "High",
                impact="High",
                likelihood="Medium",
                recommendation="Implement DNP3 Secure Authentication (SAv5) or encapsulate in IPsec/TLS tunnels.",
                remediation_priority="P2",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "DNP3" and p.get("state") == "open"],
            ))

        if "OPC UA" in open_by_protocol:
            findings.append(_finding(
                "OPC UA exposed (check security config)",
                "Medium",
                impact="High",
                likelihood="Low",
                recommendation="Disable 'None' security policy (No Encryption / No Sign); enforce Basic256Sha256 or Aes128_Sha256_RsaOaep with user authentication.",
                remediation_priority="P3",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "OPC UA" and p.get("state") == "open"],
            ))

        # 🔸 B&R Automation risks
        br_eng_ports = sorted(open_ports & {11159, 11160, 11169})
        if br_eng_ports:
            findings.append(_finding(
                "B&R Automation Studio/PVI engineering port exposed "
                "(proprietary protocol, weak/no built-in authentication)",
                "High",
                impact="Critical",
                likelihood="High",
                recommendation="Filter ports 11159, 11160, and 11169 at network boundary; restrict access strictly to authorized Automation Studio engineering workstations.",
                remediation_priority="P2",
                related_ports=br_eng_ports,
            ))

        br_safe_ports = sorted(open_ports & {50000, 51000})
        if br_safe_ports:
            findings.append(_finding(
                "B&R SafeDESIGNER exposed (safety-PLC programming access — high impact if reachable)",
                "Critical",
                impact="Critical",
                likelihood="Medium",
                recommendation="IMMEDIATELY isolate safety network; block ports 50000/51000 from all general networks; enforce physical/key-switch lockout on safety controller.",
                remediation_priority="P1",
                related_ports=br_safe_ports,
            ))

        if any("System Diagnostics Manager" in e for e in host.get("evidence", [])):
            findings.append(_finding(
                "B&R SDM diagnostics interface exposed (can leak system/firmware info)",
                "Medium",
                impact="Medium",
                likelihood="High",
                recommendation="Disable or password-protect System Diagnostics Manager (SDM) in Automation Studio configuration if not required for operations.",
                remediation_priority="P3",
                related_ports=sorted(open_ports & {80, 81, 8084}) or [80],
            ))

        if "B&R mapp View" in open_by_protocol:
            findings.append(_finding(
                "B&R mapp View HMI exposed over plain HTTP",
                "Medium",
                impact="Medium",
                likelihood="High",
                recommendation="Enable HTTPS (TLS) for mapp View web applications and redirect all HTTP requests to HTTPS.",
                remediation_priority="P3",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "B&R mapp View" and p.get("state") == "open"],
            ))

        # 🔸 IT/Access risks
        if "FTP" in open_by_protocol:
            findings.append(_finding(
                "FTP open (insecure protocol)",
                "Medium",
                impact="Medium",
                likelihood="High",
                recommendation="Disable FTP service and replace with SFTP or HTTPS; ensure anonymous access is disabled.",
                remediation_priority="P3",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "FTP" and p.get("state") == "open"],
            ))

        if "VNC" in open_by_protocol:
            findings.append(_finding(
                "VNC open (remote control risk)",
                "High",
                impact="High",
                likelihood="High",
                recommendation="Disable VNC or restrict via host firewall and VPN/SSH tunnel; enforce strong password authentication.",
                remediation_priority="P2",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "VNC" and p.get("state") == "open"],
            ))

        if "HTTP" in open_by_protocol:
            findings.append(_finding(
                "HTTP open (unencrypted web interface)",
                "Low",
                impact="Low",
                likelihood="Medium",
                recommendation="Migrate management interfaces to HTTPS (TLS) and disable plaintext HTTP.",
                remediation_priority="P4",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "HTTP" and p.get("state") == "open"],
            ))

        if "SSH" in open_by_protocol:
            findings.append(_finding(
                "SSH open (remote admin access)",
                "Low",
                impact="Medium",
                likelihood="Low",
                recommendation="Enforce key-based authentication, disable root login, and restrict access via management ACL.",
                remediation_priority="P4",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "SSH" and p.get("state") == "open"],
            ))

        if "SNMP" in open_by_protocol:
            findings.append(_finding(
                "SNMP open (potential info disclosure, check for default community strings)",
                "Medium",
                impact="Medium",
                likelihood="High",
                recommendation="Upgrade to SNMPv3 with authPriv encryption; change default community strings and disable write access.",
                remediation_priority="P3",
                related_ports=[p["port"] for p in ot_ports if p.get("protocol") == "SNMP" and p.get("state") == "open"],
            ))

        # 🔸 Contextual risk
        if len(open_ports) > 2:
            findings.append(_finding(
                "Multiple services exposed (larger attack surface)",
                "Low",
                impact="Low",
                likelihood="Medium",
                recommendation="Disable unnecessary network services according to the principle of least functionality.",
                remediation_priority="P4",
                related_ports=sorted(open_ports),
            ))

        # 🔸 Known-CVE correlation (model/firmware/evidence-aware)
        findings.extend(cve_engine.correlate(host))

        host["risks"] = findings
        host["risk_severity"] = _highest_severity(findings) or "None"
        host["risk_score"] = _calculate_risk_score(findings, host.get("type"))
        host["summary"] = _generate_host_summary(host, findings, host["risk_score"])

    return data
