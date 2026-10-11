# ot_recon/core/enricher.py
#
# Enriches raw scanned ports with OT protocol intelligence, service
# categories (OT vs. IT), confidence ratings, and authentication profiles.
# Produces both the legacy `ot_ports` array (for backwards compatibility)
# and the unified `services` array (containing all scanned ports with rich metadata).

import yaml
from ot_recon.core.paths import PORTS_YAML


def load_port_map():
    with open(PORTS_YAML, "r") as f:
        return yaml.safe_load(f)


# Service aliases from Nmap -> normalized protocol names.
# NOTE: these strings must match classifier.py / risk.py exactly.
SERVICE_MAP = {
    "mbap": "Modbus",
    "http": "HTTP",
    "https": "HTTPS",
    "ssl/http": "HTTPS",
    "iso-tsap": "S7",
    "ssh": "SSH",
    "ftp": "FTP",
    "EtherNetIP-2": "EtherNet/IP",
    "EtherNetIP": "EtherNet/IP",
    "enip": "EtherNet/IP",
    "opcua": "OPC UA",
    "opc-ua": "OPC UA",
    "vnc": "VNC",
    "snmp": "SNMP",
    "dnp3": "DNP3",
}

OT_PROTOCOLS = {
    "Modbus",
    "S7",
    "EtherNet/IP",
    "EtherNet/IP-IO",
    "DNP3",
    "OPC UA",
    "B&R ANSL",
    "B&R PVI",
    "B&R SafeDESIGNER",
    "B&R mapp View",
    "B&R mapp Cockpit",
}

IT_PROTOCOLS = {
    "HTTP",
    "HTTPS",
    "SSH",
    "FTP",
    "SNMP",
    "VNC",
}

# Standard industrial security profiles for detected protocols
AUTH_MAP = {
    # OT protocols with zero native authentication in basic spec
    "Modbus": "none",
    "S7": "none",
    "EtherNet/IP": "none",
    "EtherNet/IP-IO": "none",
    "DNP3": "none",
    "B&R ANSL": "none",
    "B&R PVI": "none",
    "B&R SafeDESIGNER": "none",
    # Cleartext IT protocols
    "HTTP": "cleartext",
    "FTP": "cleartext",
    "B&R mapp View": "cleartext",
    # Encrypted IT protocols
    "HTTPS": "encrypted",
    "SSH": "encrypted",
    # Weak authentication
    "SNMP": "weak",
    "VNC": "weak",
    # Configurable security policies (e.g. None vs. Basic256Sha256)
    "OPC UA": "configurable",
}


def enrich(data):

    port_map = load_port_map()

    for host in data:

        enriched_ot_ports = []
        unified_services = []

        for p in host.get("ports", []):

            port = p["port"]  # int - port_map keys from YAML parse as ints too
            state = p["state"]
            service = p.get("service", "unknown")
            transport = p.get("transport", "tcp")
            version = p.get("version")

            protocol = None
            confidence = "Low"

            # Method 1 -> Port-based detection
            if port in port_map:
                protocol = port_map[port]["protocol"]
                confidence = "Medium"

            # Method 2 -> Service fingerprint detection (overrides port lookup)
            if service in SERVICE_MAP:
                protocol = SERVICE_MAP[service]
                confidence = "High"

            # Determine category
            if protocol in OT_PROTOCOLS:
                category = "ot"
            elif protocol in IT_PROTOCOLS or service in IT_PROTOCOLS:
                category = "it"
            else:
                category = "unknown"

            # Determine authentication security posture
            if state == "open":
                auth_status = AUTH_MAP.get(protocol, "unknown")
            else:
                auth_status = "none"

            # Build unified service object for every scanned port
            unified_services.append({
                "port": port,
                "transport": transport,
                "state": state,
                "service": service,
                "protocol": protocol,
                "category": category,
                "confidence": confidence if protocol else "Low",
                "authentication": auth_status,
                "version": version,
            })

            # Maintain legacy ot_ports list for backwards compatibility
            if protocol:
                enriched_ot_ports.append({
                    "port": port,
                    "state": state,
                    "service": service,
                    "protocol": protocol,
                    "confidence": confidence,
                    "transport": transport,
                })

        host["ot_ports"] = enriched_ot_ports
        host["services"] = unified_services

    return data