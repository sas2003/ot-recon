# ot_recon/core/enricher.py

import yaml
from ot_recon.core.paths import PORTS_YAML


def load_port_map():
    with open(PORTS_YAML, "r") as f:
        return yaml.safe_load(f)


# Service aliases from Nmap → normalized protocol names
SERVICE_MAP = {
    "mbap": "Modbus",
    "http": "HTTP",
    "iso-tsap": "S7",
    "ssh": "SSH",
    "ftp": "FTP",
    "EtherNetIP-2": "EtherNet/IP",
    "EtherNetIP": "EtherNet/IP",
    "opcua": "OPC UA",
    "vnc": "VNC"
}


def enrich(data):

    port_map = load_port_map()

    for host in data:

        enriched_ports = []

        for p in host["ports"]:

            port = str(p["port"])
            state = p["state"]
            service = p.get("service", "unknown")

            protocol = None
            confidence = "Low"

            # Method 1 → Port-based detection
            if port in port_map:
                protocol = port_map[port]["protocol"]
                confidence = "Medium"

            # Method 2 → Service fingerprint detection
            if service in SERVICE_MAP:
                protocol = SERVICE_MAP[service]
                confidence = "High"

            if protocol:

                enriched_ports.append({
                    "port": p["port"],
                    "state": state,
                    "service": service,
                    "protocol": protocol,
                    "confidence": confidence
                })

        host["ot_ports"] = enriched_ports

    return data