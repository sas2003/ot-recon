# ot_recon/core/classifier.py
#
# Classifies assets using evidence-first rules into a strict, standardized
# device-type controlled vocabulary (PLC, Safety PLC, HMI, Field Device,
# Industrial Server, Unknown). Provides quantitative confidence scores (0-100)
# and explicit detection_method / evidence_based metadata.

import re

CONTROLLED_TYPES = [
    "PLC",
    "Safety PLC",
    "HMI",
    "Field Device",
    "Industrial Server",
    "Unknown",
]

CONFIDENCE_SCORES = {
    "Very High": 95,
    "High": 80,
    "Medium": 50,
    "Low": 20,
}


def classify(data):

    for host in data:

        evidence = host.get("evidence", [])

        # Check ot_ports (or fallback to services) for open protocol list
        protocols = [
            p["protocol"]
            for p in host.get("ot_ports", [])
            if p.get("protocol") and p.get("state", "open") == "open"
        ]
        if not protocols and "services" in host:
            protocols = [
                s["protocol"]
                for s in host["services"]
                if s.get("protocol") and s.get("state", "open") == "open"
            ]

        #
        # Evidence-based classification (Active Probes / Deep Fingerprints)
        #

        if (
            any("SIMATIC HMI" in e for e in evidence)
            or any("Human-Machine Interface" in e for e in evidence)
            or any("PanelView" in e for e in evidence)
            or (host.get("model") and "panelview" in str(host["model"]).lower())
        ):
            host["type"] = "HMI"
            host["confidence"] = "Very High"
            host["detection_method"] = "active_probe"
            host["evidence_based"] = True

        elif (
            any("SafeDESIGNER" in e for e in evidence)
            or any("GuardLogix" in e for e in evidence)
            or (host.get("model") and "guardlogix" in str(host["model"]).lower())
        ):
            host["type"] = "Safety PLC"
            host["confidence"] = "High"
            host["detection_method"] = "active_probe"
            host["evidence_based"] = True

        elif any("S7comm response confirmed (PLC/CPU)" in e for e in evidence) or any(
            "Programmable Logic Controller" in e for e in evidence
        ):
            host["type"] = "PLC"
            host["confidence"] = "Very High"
            host["detection_method"] = "active_probe"
            host["evidence_based"] = True

        elif any(
            re.search(
                r"Communication[s]?\s+Adapter|Ethernet\s+Adapter|Network\s+Adapter|AC\s+Drive|Motor\s+Drive|Discrete\s+I/O",
                e,
                re.IGNORECASE,
            )
            for e in evidence
        ):
            host["type"] = "Field Device"
            host["confidence"] = "Very High"
            host["detection_method"] = "active_probe"
            host["evidence_based"] = True

        elif (
            host.get("model")
            and (
                re.search(r"\b17\d\d-(?:AENT|AENTR|EN2T|EN2TR|EN3T|EN3TR|ENBT|ENET|EWEB|ENTR)\b", str(host["model"]), re.IGNORECASE)
                or re.search(r"\b(?:adapter|ethernet\s*adapter|comm\w*\s*adapter)\b", str(host["model"]), re.IGNORECASE)
            )
        ):
            host["type"] = "Field Device"
            host["confidence"] = "High"
            host["detection_method"] = "active_probe"
            host["evidence_based"] = True

        #
        # B&R Automation (evidence-based)
        #

        elif any("mapp View" in e for e in evidence):
            host["type"] = "HMI"
            host["confidence"] = "High"
            host["detection_method"] = "active_probe"
            host["evidence_based"] = True

        elif any("System Diagnostics Manager" in e for e in evidence):
            # SDM runs directly on the B&R PLC/CPU runtime
            host["type"] = "PLC"
            host["confidence"] = "High"
            host["detection_method"] = "active_probe"
            host["evidence_based"] = True

        elif host.get("vendor") == "B&R Automation (unconfirmed - port signature only)":
            # Proprietary engineering port detected without HTTP confirmation
            host["type"] = "PLC"
            host["confidence"] = "Medium"
            host["detection_method"] = "port_signature"
            host["evidence_based"] = True

        #
        # Protocol-based Fallback Heuristics (Lower Confidence)
        #

        elif "Modbus" in protocols:
            host["type"] = "Field Device"
            host["confidence"] = "Medium"
            host["detection_method"] = "heuristic"
            host["evidence_based"] = False

        elif "S7" in protocols:
            host["type"] = "PLC"
            host["confidence"] = "Medium"
            host["detection_method"] = "heuristic"
            host["evidence_based"] = False

        elif "EtherNet/IP" in protocols:
            host["type"] = "PLC"
            host["confidence"] = "Medium"
            host["detection_method"] = "heuristic"
            host["evidence_based"] = False

        elif "OPC UA" in protocols:
            host["type"] = "Industrial Server"
            host["confidence"] = "Medium"
            host["detection_method"] = "heuristic"
            host["evidence_based"] = False

        else:
            host["type"] = "Unknown"
            host["confidence"] = "Low"
            host["detection_method"] = "none"
            host["evidence_based"] = False

        # Quantify confidence score (0-100)
        host["confidence_score"] = CONFIDENCE_SCORES.get(
            host["confidence"], 20
        )

    return data